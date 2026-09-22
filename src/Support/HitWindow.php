<?php

declare(strict_types=1);

namespace Watchtower\Support;

use Illuminate\Contracts\Cache\Repository;
use Illuminate\Support\Facades\Cache;

/**
 * Per-IP hit counting for the real-time detectors, in a decaying window.
 *
 * Two kinds of key, both under the configured cache prefix and both
 * decaying with the detector's own window:
 *
 * - `{prefix}:hits:{detector}:{ip}` — the counter.
 * - `{prefix}:users:{detector}:{ip}` — the signed-in users seen from that
 *   address while it was accumulating hits, which is what the shared-IP
 *   guard reads for detectors that have no log table to query.
 *
 * Nothing here is written for traffic that doesn't match a detector: an
 * address only gets a counter once it has already done something a
 * detector counts.
 *
 * The counter is Laravel's RateLimiter::increment() inlined, minus its
 * `:timer` sidecar. RateLimiter keeps that key so availableIn() can report
 * how long a caller must wait; nothing here ever asks, and writing it cost a
 * round trip on every hit and another on every clear — on a path an attacker
 * sets the pace of. What is kept is the part that matters: the repair for a
 * key that expires mid-hit, which on some stores comes back with no TTL at
 * all, leaving a counter that never decays and pins an address at its
 * threshold forever.
 */
class HitWindow
{
    /**
     * Cap on the user ids remembered per window.
     *
     * ponytail: a plain capped list, not a HyperLogLog or a set type, because
     * the guard only needs to know whether distinct users reach a threshold
     * that defaults to 3. The ceiling is that an address with more than this
     * many users in one window reports exactly this many; since every
     * sensible threshold is far below the cap, "at least MAX_USERS" and
     * "exactly MAX_USERS" lead to the same decision. Raise the cap if a
     * threshold ever approaches it.
     */
    private const MAX_USERS = 20;

    /**
     * Count one hit for this detector and address, and return the running
     * total inside the window.
     */
    public function hit(string $detector, string $ip, int $windowSeconds): int
    {
        $cache = $this->cache();
        $key = $this->key('hits', $detector, $ip);

        // add() is what opens the window: it sets the TTL the counter decays
        // with, and is a no-op once the window is running, so the window stays
        // fixed from its first hit rather than sliding with every one.
        $added = $cache->add($key, 0, $windowSeconds);
        $hits = (int) $cache->increment($key);

        // add() found the key but increment() had to recreate it, so it
        // expired between the two and came back without a TTL. Stamp the
        // window back on — a counter with no expiry never decays. A store
        // whose increment() refuses a missing key reads as 0 through the
        // cast, which lands here too and is likewise a fresh window of one.
        if (! $added && $hits <= 1) {
            $cache->put($key, 1, $windowSeconds);

            return 1;
        }

        return $hits;
    }

    /**
     * Remember a signed-in user seen from this address while it was
     * accumulating hits.
     *
     * Skipped once the id is already known or the cap is reached, so a
     * single user hammering a detector writes the set once rather than on
     * every hit.
     *
     * ⚠️ Read-modify-write, so two concurrent hits can lose one id. The
     * guard is a heuristic about how many people a block would hit, and
     * losing an id can only make the count too low — which is the direction
     * that fails safe for the *address*, not for the block. A lock on the
     * request path would cost more than the accuracy is worth.
     */
    public function recordUser(string $detector, string $ip, int|string $userId, int $windowSeconds): void
    {
        $key = $this->key('users', $detector, $ip);
        $cache = $this->cache();
        $now = time();

        [$expires, $seen] = $this->entry($cache->get($key), $now);

        if ($expires <= $now) {
            $expires = $now + $windowSeconds;
        }

        $id = (string) $userId;

        if (count($seen) >= self::MAX_USERS || in_array($id, $seen, true)) {
            return;
        }

        $seen[] = $id;

        // Keep the expiry the set was opened with rather than writing
        // $windowSeconds again. The hit counter's window is fixed from its
        // first hit — hit() opens it with add(), which is a no-op
        // afterwards — so re-stamping here would let the user set
        // outlive the counter it belongs to. A user arriving late in one
        // window would then still be counted in the next, inflating the
        // distinct-user count with people who generated none of its
        // traffic, and biasing the guard toward standing a real block down.
        $cache->put($key, ['expires' => $expires, 'ids' => $seen], max(1, $expires - $now));
    }

    /**
     * The signed-in users seen from this address in the current window.
     *
     * Read-only. The threshold path wants close() instead, which answers the
     * same question about the window it is dropping.
     *
     * @return list<string>
     */
    public function users(string $detector, string $ip): array
    {
        // The stored expiry is authoritative, not the cache TTL: a store that
        // rounds TTLs up, or a set written just before the boundary, can
        // still hand back an entry whose window has closed. entry() reads a
        // closed one as empty.
        [, $seen] = $this->entry($this->cache()->get($this->key('users', $detector, $ip)), time());

        return $seen;
    }

    /**
     * Close this address's window, reporting the signed-in users it had
     * accumulated.
     *
     * Clearing returns what it dropped rather than leaving the caller to read
     * it first, because reading it afterwards gets nobody — silently, since
     * "no users" is a perfectly ordinary answer. That made the correct order
     * a comment to obey rather than something the API enforced.
     *
     * Closing on every threshold crossing, not only on one that blocked, is
     * what stops a held-back detector re-deciding per request — see
     * AutoBlockService::blockDetected(), which explains what that costs.
     *
     * @return list<string>
     */
    public function close(string $detector, string $ip): array
    {
        $cache = $this->cache();
        $usersKey = $this->key('users', $detector, $ip);

        [, $seen] = $this->entry($cache->get($usersKey), time());

        $cache->forget($this->key('hits', $detector, $ip));

        // Most detector traffic is anonymous and never opened a user set, so
        // deleting that key unconditionally spends a round trip on a key that
        // was never written. A set that has gone stale reads as empty here
        // too and is left for the store's own TTL to reap.
        if ($seen !== []) {
            $cache->forget($usersKey);
        }

        return $seen;
    }

    /**
     * Unpack a stored user set into [expiry, ids], tolerating anything that
     * isn't one — an absent key, or a value left by an older version.
     *
     * @return array{0: int, 1: list<string>}
     */
    private function entry(mixed $value, int $now): array
    {
        if (! is_array($value) || ! isset($value['expires'], $value['ids']) || ! is_array($value['ids'])) {
            return [0, []];
        }

        $expires = (int) $value['expires'];

        return $expires > $now
            ? [$expires, array_values(array_map(strval(...), $value['ids']))]
            : [0, []];
    }

    private function key(string $kind, string $detector, string $ip): string
    {
        $prefix = (string) config('watchtower.cache.key', 'watchtower:blacklist');

        return "{$prefix}:{$kind}:{$detector}:{$ip}";
    }

    /**
     * Resolved per call so a runtime config change takes effect, matching
     * BlacklistCache. `Cache::store(null)` is the application default.
     */
    private function cache(): Repository
    {
        $store = config('watchtower.cache.store');

        return Cache::store(is_string($store) ? $store : null);
    }
}
