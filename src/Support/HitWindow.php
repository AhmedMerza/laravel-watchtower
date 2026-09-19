<?php

declare(strict_types=1);

namespace Watchtower\Support;

use Illuminate\Cache\RateLimiter;
use Illuminate\Contracts\Cache\Repository;
use Illuminate\Support\Facades\Cache;

/**
 * Per-IP hit counting for the real-time detectors, in a decaying window.
 *
 * Two kinds of key, both under the configured cache prefix and both
 * decaying with the detector's own window:
 *
 * - `{prefix}:hits:{detector}:{ip}` — the counter, via Laravel's own
 *   RateLimiter (which also writes its `:timer` sidecar).
 * - `{prefix}:users:{detector}:{ip}` — the signed-in users seen from that
 *   address while it was accumulating hits, which is what the shared-IP
 *   guard reads for detectors that have no log table to query.
 *
 * Nothing here is written for traffic that doesn't match a detector: an
 * address only gets a counter once it has already done something a
 * detector counts.
 *
 * RateLimiter rather than a bare add()+increment() pair because a key that
 * expires between those two calls comes back on some stores with no TTL at
 * all — a counter that never decays, pinning an address at its threshold
 * forever. RateLimiter re-puts the key with its decay in exactly that case.
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
        return $this->limiter()->hit($this->key('hits', $detector, $ip), $windowSeconds);
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
        // first hit — RateLimiter sets its timer with add(), which is a
        // no-op afterwards — so re-stamping here would let the user set
        // outlive the counter it belongs to. A user arriving late in one
        // window would then still be counted in the next, inflating the
        // distinct-user count with people who generated none of its
        // traffic, and biasing the guard toward standing a real block down.
        $cache->put($key, ['expires' => $expires, 'ids' => $seen], max(1, $expires - $now));
    }

    /**
     * The signed-in users seen from this address in the current window.
     *
     * @return list<string>
     */
    public function users(string $detector, string $ip): array
    {
        $now = time();

        [$expires, $seen] = $this->entry($this->cache()->get($this->key('users', $detector, $ip)), $now);

        // The stored expiry is authoritative, not the cache TTL: a store
        // that rounds TTLs up, or a set written just before the boundary,
        // can still hand back an entry whose window has closed.
        return $expires > $now ? $seen : [];
    }

    /**
     * Drop an address's counter and user set — called once it is blocked, so
     * a later window starts from zero rather than from a total that already
     * crossed the threshold.
     */
    public function forget(string $detector, string $ip): void
    {
        $this->limiter()->clear($this->key('hits', $detector, $ip));
        $this->cache()->forget($this->key('users', $detector, $ip));
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

    private function limiter(): RateLimiter
    {
        return new RateLimiter($this->cache());
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
