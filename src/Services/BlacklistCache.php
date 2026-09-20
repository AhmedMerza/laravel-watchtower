<?php

declare(strict_types=1);

namespace Watchtower\Services;

use Carbon\Carbon;
use Illuminate\Contracts\Cache\Repository;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Log;
use Symfony\Component\HttpFoundation\IpUtils;
use Watchtower\Models\BlacklistedIp;
use Watchtower\Support\BlockScope;
use Watchtower\Support\FailureWindow;
use Watchtower\Support\IpRange;

/**
 * Stores the active blacklist in Laravel's cache so the request-path
 * blocked-IP check reads two cache keys and never the DB.
 *
 * Three kinds of key:
 *
 * - `{prefix}:ip:{target}` — one per single IP, and one per IPv6 range at
 *   the configured block prefix (`{prefix}:ip:2001:db8::/64`). A request is
 *   looked up by its own key, so these stay O(1) however many there are,
 *   which matters because auto-block only ever produces these.
 * - `{prefix}:_ranges` — every other range, in one list, with the IPv6
 *   prefix the keys above were built for. It's read on every request, and
 *   every rebuild writes it, so its absence is what marks the cache cold.
 * - `{prefix}:_index` — the targets that have their own key, read only by
 *   `rebuild()` so it can forget stale entries on any cache driver. We
 *   can't rely on `Cache::tags()`: file and database stores don't support
 *   tagging, and dropping those stores is exactly what this avoids.
 *
 * A scoped block lives in its own namespace, `{prefix}:s:{scope}:…`, with
 * the same three key kinds inside it. The global middleware only ever reads
 * the global namespace, so a request to a route with no scope middleware
 * costs exactly what it did before scopes existed. A scoped route pays for
 * one more namespace, and only the one it names.
 */
class BlacklistCache
{
    private string $keyPrefix;

    private int $ttlSeconds;

    private ?string $store;

    public function __construct()
    {
        $config = config('watchtower.cache', []);
        $this->keyPrefix = (string) ($config['key'] ?? 'watchtower:blacklist');
        $this->ttlSeconds = (int) ($config['ttl_hours'] ?? 24) * 3600;
        $this->store = $config['store'] ?? null;
    }

    /**
     * Resolve the configured cache repository. `null` falls back to the
     * application's default cache store. Resolved per-call so a runtime
     * config change (e.g. tests using `config()->set(...)`) takes effect
     * without re-instantiating the service.
     */
    private function cache(): Repository
    {
        return $this->store === null
            ? Cache::store()
            : Cache::store($this->store);
    }

    /**
     * The key namespace for a scope. The global scope keeps the bare prefix,
     * so every key written before scopes existed is still the key read now —
     * upgrading does not cold-start the cache.
     */
    private function prefix(string $scope): string
    {
        return $scope === BlockScope::GLOBAL
            ? $this->keyPrefix
            : $this->keyPrefix.':s:'.$scope;
    }

    private function key(string $target, string $scope = BlockScope::GLOBAL): string
    {
        return $this->prefix($scope).':ip:'.$target;
    }

    private function indexKey(string $scope = BlockScope::GLOBAL): string
    {
        return $this->prefix($scope).':_index';
    }

    private function rangesKey(string $scope = BlockScope::GLOBAL): string
    {
        return $this->prefix($scope).':_ranges';
    }

    /**
     * Check whether an already-normalized IP is currently blocked, in one
     * scope. Two cache reads, no DB hit — unless the cache is cold, in which
     * case it's warmed from the DB first.
     *
     * The default scope is the global one, so the blocking middleware asks
     * the same question it always did. A scoped lookup reads a different pair
     * of keys and never consults the global ones: a globally blocked address
     * has already been turned away by the global middleware before any
     * scoped middleware runs.
     */
    public function isBlocked(string $ip, string $scope = BlockScope::GLOBAL): bool
    {
        $cache = $this->cache();
        $ranges = $cache->get($this->rangesKey($scope));

        if ((! is_array($ranges) || ! empty($ranges['partial'])) && $this->warm()) {
            $ranges = $cache->get($this->rangesKey($scope));
        }

        $now = now()->getTimestamp();
        $active = array_keys(array_filter(
            (array) ($ranges['ranges'] ?? []),
            fn ($expires) => $expires === 0 || $expires > $now,
        ));

        if ($active !== [] && IpUtils::checkIp($ip, $active)) {
            return true;
        }

        $ipv6Prefix = (int) ($ranges['ipv6_prefix'] ?? IpRange::ipv6BlockPrefix());
        $target = str_contains($ip, ':') && $ipv6Prefix < 128
            ? IpRange::canonical("{$ip}/{$ipv6Prefix}") ?? $ip
            : $ip;

        $value = $cache->get($this->key($target, $scope));

        if ($value === null) {
            return false;
        }

        // Empty string = permanent block (no expiry)
        if ($value === '') {
            return true;
        }

        // ISO-8601 string = temporary block, check if still active
        return now()->lt(Carbon::parse($value));
    }

    /**
     * Rebuild the cache from the DB.
     * Called after every block/unblock, after watchtower:sync, and when a
     * lookup finds the cache cold.
     *
     * Clears stale entries by iterating the previous index, then writes
     * fresh per-target keys, the index, and the range list — in that order,
     * because the range list is what marks the cache warm. If the DB read
     * fails (e.g. migration not run yet), the existing cache state is left
     * intact — we'd rather serve stale-but-correct entries than wipe
     * everything.
     *
     * Each row is filed by the IPv6 block prefix configured now, not the one
     * it was blocked under, and the range list records which prefix that
     * was so lookups agree with it until the next rebuild.
     *
     * ⚠️ Atomicity caveat: rebuild is NOT atomic across the cache backend.
     * If the process is killed between steps — or if the cache backend
     * partially fails mid-iteration — the cache can end up in an
     * inconsistent state:
     *
     *   - Worst case: an IP unblocked in the DB but whose forget call
     *     failed remains in the cache as "yes blocked" until its TTL
     *     expires (default 24h). A legitimate user is locked out for
     *     that window.
     *   - The TTL safety net bounds the worst case; subsequent rebuilds
     *     read the new index (written before the range list) and forget
     *     the right keys on the next pass.
     *
     * This trade-off is accepted for v1 because (a) rebuilds are fast
     * (sub-millisecond on Redis for typical blocklists), (b) crashes
     * mid-rebuild are rare, and (c) the alternative — a versioned key
     * prefix — adds an extra cache `get` to the request path. Revisit if
     * real-world reports show stale-entry issues; the migration path is
     * a versioned-prefix scheme that orphans old keys naturally via TTL.
     *
     * @return bool false if the DB read failed and the cache was left as-is.
     */
    public function rebuild(): bool
    {
        try {
            $blocks = BlacklistedIp::active()->get(['ip', 'expires_at', 'scope']);
        } catch (\Throwable $e) {
            Log::channel(config('watchtower.log_channel', 'stack'))
                ->warning('Watchtower: cache rebuild failed, keeping existing cache data', [
                    'error' => $e->getMessage(),
                ]);

            return false;
        }

        $ipv6Prefix = IpRange::ipv6BlockPrefix();

        $byScope = [];

        foreach ($blocks as $block) {
            $byScope[(string) $block->scope][] = $block;
        }

        // One DB read covers every scope, which is why callers that drive
        // rebuild() themselves — watchtower:cleanup, watchtower:sync — stay
        // correct without knowing scopes exist.
        foreach ($this->namespacesToWrite($byScope) as $scope) {
            $this->rebuildScope($scope, $byScope[$scope] ?? [], $ipv6Prefix);
        }

        return true;
    }

    /**
     * Which namespaces a rebuild writes: the global one, every declared
     * scope, and any scope that still has rows.
     *
     * Declared scopes are written even when nothing uses them. The range key
     * is what marks a namespace warm, so a scope without one reads as cold on
     * every request to its routes, and every one of those requests answers
     * that by rebuilding from the DB — the exact full-table read the cache
     * exists to avoid.
     *
     * A scope with rows but no longer in config is written too. It keeps
     * enforcing until someone unblocks it, rather than silently lapsing
     * because a config line was deleted.
     *
     * @param  array<string, list<BlacklistedIp>>  $byScope
     * @return list<string>
     */
    private function namespacesToWrite(array $byScope): array
    {
        // BlockScope::declared(), not a second read of the config. That class
        // owns the vocabulary and trims each name; re-parsing here without
        // the trim meant `'scopes' => ['auth ']` stored blocks under `auth`
        // while writing this namespace under `auth ` — so the real namespace
        // never got a range key, and every request to its routes read it as
        // cold and rebuilt the whole blocklist from the DB.
        $declared = BlockScope::declared();

        return array_values(array_unique(array_merge(
            [BlockScope::GLOBAL],
            $declared,
            array_map('strval', array_keys($byScope)),
        )));
    }

    /**
     * Write one namespace: forget the previous generation's keys so unblocked
     * IPs don't sit in the cache until their TTL expires, then write this
     * one's per-target keys, index and range list.
     *
     * @param  list<BlacklistedIp>  $blocks
     */
    private function rebuildScope(string $scope, array $blocks, int $ipv6Prefix): void
    {
        $cache = $this->cache();

        foreach ((array) $cache->get($this->indexKey($scope), []) as $old) {
            $cache->forget($this->key((string) $old, $scope));
        }

        $index = [];
        $ranges = [];

        foreach ($blocks as $block) {
            $target = IpRange::canonical($block->ip);

            if ($target === null) {
                continue;
            }

            if ($this->hasOwnKey($target, $ipv6Prefix)) {
                $cache->put($this->key($target, $scope), $this->value($block), $this->ttlSeconds);
                $index[] = $target;
            } else {
                $ranges[$target] = $block->expires_at?->getTimestamp() ?? 0;
            }
        }

        $cache->put($this->indexKey($scope), $index, $this->ttlSeconds);

        $this->putRanges([
            'ipv6_prefix' => $ipv6Prefix,
            'ranges'      => $ranges,
            'expires'     => now()->addSeconds($this->ttlSeconds)->getTimestamp(),
        ], $scope);
    }

    /**
     * Write one new block into the cache, the cheap way wherever that's safe.
     *
     * A single address — and an IPv6 network already at the block prefix —
     * owns its key, so one put() is the entire write and the other entries
     * are left alone. That matters because auto-block only ever produces
     * these: a scanner storm creating hundreds of blocks would otherwise
     * trigger hundreds of full rebuilds, each one re-reading every active
     * row, exactly when the app is least able to afford it.
     *
     * A wider range has no key of its own; it lives in the shared range
     * list, which put() can only update by reading it and writing it back.
     * Rebuilding from the DB keeps that list authoritative and avoids two
     * concurrent range blocks losing one of the two, so ranges keep paying
     * for a rebuild — they're made by hand, one at a time.
     */
    public function write(BlacklistedIp $block): void
    {
        $target = IpRange::canonical($block->ip);

        if ($target !== null && $this->hasOwnKey($target, IpRange::ipv6BlockPrefix())) {
            $this->put($block);

            return;
        }

        if (! $this->rebuild()) {
            $this->put($block);
        }
    }

    /**
     * Write one block's entry without reading the DB — the write path for a
     * single address, and the fallback for a block whose rebuild() failed so
     * it takes effect anyway.
     *
     * A key written here is deliberately left out of the index: rewriting
     * the index would restart its TTL, so it would outlive the entries it
     * lists. The cost is that no later rebuild forgets it, which write()
     * now makes true of most of the blocklist rather than the rare entry
     * left behind by a failed rebuild. Two guarantees carry that weight:
     *
     * - A temporary block's entry holds its own expiry, so it stops
     *   matching on its own. watchtower:cleanup only ever deletes rows
     *   that have one, which is why a key it leaves behind is harmless.
     * - A permanent block has no expiry to fall back on, and is only ever
     *   removed through BlacklistService::unblock(), which calls forget()
     *   for each target before rebuilding. watchtower:sync never deletes.
     *
     * So deleting a permanent block's row directly — bypassing unblock() —
     * is the one way to strand a cached block, and it stays stranded until
     * the TTL expires.
     *
     * A range is added to the range list, which keeps its original expiry
     * for the same reason. If there's no list, the cache is cold and the DB
     * is failing; the list written then is marked partial, so lookups keep
     * trying to warm the cache rather than trusting it.
     *
     * ⚠️ Reading the list, changing one entry and writing it back isn't
     * atomic either, so two of these at once can lose one of the changes.
     * The windows are narrow — this runs only when the DB write landed and
     * the read right after it didn't, and every forget() is followed by a
     * rebuild() that rewrites the list from the DB — and a lock on the
     * request path would cost more than it saves.
     */
    public function put(BlacklistedIp $block): void
    {
        $target = IpRange::canonical($block->ip);

        if ($target === null) {
            return;
        }

        $scope = (string) $block->scope;
        $cache = $this->cache();
        $ranges = $cache->get($this->rangesKey($scope));

        if ($this->hasOwnKey($target, (int) ($ranges['ipv6_prefix'] ?? IpRange::ipv6BlockPrefix()))) {
            $cache->put($this->key($target, $scope), $this->value($block), $this->ttlSeconds);

            return;
        }

        if (! is_array($ranges)) {
            $ranges = [
                'ipv6_prefix' => IpRange::ipv6BlockPrefix(),
                'ranges'      => [],
                'expires'     => now()->addSeconds($this->ttlSeconds)->getTimestamp(),
                'partial'     => true,
            ];
        }

        $ranges['ranges'][$target] = $block->expires_at?->getTimestamp() ?? 0;
        $this->putRanges($ranges, $scope);
    }

    /**
     * Forget one target's entry in one scope, without reading the DB.
     * See put().
     */
    public function forget(string $target, string $scope = BlockScope::GLOBAL): void
    {
        $cache = $this->cache();
        $cache->forget($this->key($target, $scope));

        $ranges = $cache->get($this->rangesKey($scope));

        if (isset($ranges['ranges'][$target])) {
            unset($ranges['ranges'][$target]);
            $this->putRanges($ranges, $scope);
        }
    }

    /**
     * Rebuild a cold cache from the DB, and say whether it did.
     *
     * Runs inside a lookup, so it must never throw: a cache backend error
     * (Redis down, the cache table not migrated yet) or a DB read failure
     * skips the warm-up rather than failing the request. The failure
     * surfaces via the configured log channel.
     *
     * Every lookup finds a cold cache until this succeeds, so a failure
     * stands the warm-up down for a minute. Otherwise an outage repeats the
     * same doomed round-trip and writes a warning on every single request,
     * which fills the disk while the backend is already down.
     */
    private function warm(): bool
    {
        if (FailureWindow::isOpen('warm')) {
            return false;
        }

        try {
            // rebuild() logs and swallows its own DB failure, so ask it.
            if ($this->rebuild()) {
                return true;
            }
        } catch (\Throwable $e) {
            Log::channel(config('watchtower.log_channel', 'stack'))
                ->warning('Watchtower: cache warm-up failed, skipping it', [
                    'error' => $e->getMessage(),
                ]);
        }

        FailureWindow::open('warm');

        return false;
    }

    /** Whether a target gets its own key, rather than a place in the range list. */
    private function hasOwnKey(string $target, int $ipv6Prefix): bool
    {
        [$address, $length] = IpRange::split($target);

        return $length === (str_contains($address, ':') ? $ipv6Prefix : 32);
    }

    /** Empty string for a permanent block, ISO-8601 expiry for a temporary one. */
    private function value(BlacklistedIp $block): string
    {
        return $block->expires_at ? $block->expires_at->toIso8601String() : '';
    }

    /** Write one scope's range list, keeping the expiry it was first written with. */
    private function putRanges(array $ranges, string $scope = BlockScope::GLOBAL): void
    {
        $expires = $ranges['expires'] ?? now()->addSeconds($this->ttlSeconds)->getTimestamp();

        $this->cache()->put($this->rangesKey($scope), $ranges, Carbon::createFromTimestamp($expires));
    }
}
