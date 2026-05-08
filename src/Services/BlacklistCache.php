<?php

declare(strict_types=1);

namespace Watchtower\Services;

use Carbon\Carbon;
use Illuminate\Cache\Repository;
use Illuminate\Support\Facades\Cache;
use Watchtower\Models\BlacklistedIp;

/**
 * Stores the active blacklist in Laravel's cache so the request-path
 * blocked-IP check is one cache lookup with no DB hit.
 *
 * The cache uses per-IP keys (`{prefix}:ip:{ip}`) plus a sidecar index
 * key (`{prefix}:_index`) that tracks the set of currently-blocked IPs.
 * The index lets `rebuild()` clear stale entries on any cache driver —
 * we can't rely on `Cache::tags()` because file and database stores
 * don't support tagging, and dropping support for those is exactly what
 * this design avoids.
 *
 * Trade-off vs. the previous single-Redis-Hash design:
 *
 * - Request-time cost is unchanged: one cache `get` per request.
 * - Rebuilds do N+1 writes (N IPs + 1 index) instead of a single HMSET.
 *   Rebuilds are rare (only on block/unblock/sync), so this is fine.
 * - Index ordering isn't load-bearing — we never iterate it for
 *   correctness, only to forget stale entries on rebuild.
 */
class BlacklistCache
{
    /**
     * Set to true after the deprecation warning for `cache.connection` has
     * been emitted, so we surface it once per process rather than every
     * time the service is resolved (and especially not once per request).
     */
    private static bool $deprecationWarningEmitted = false;

    private string $keyPrefix;

    private string $indexKey;

    private int $ttlSeconds;

    private ?string $store;

    public function __construct()
    {
        $config = config('watchtower.cache', []);
        $this->keyPrefix = (string) ($config['key'] ?? 'watchtower:blacklist');
        $this->indexKey = $this->keyPrefix.':_index';
        $this->ttlSeconds = (int) ($config['ttl_hours'] ?? 24) * 3600;
        $this->store = $config['store'] ?? null;

        $this->warnIfDeprecatedConnectionConfigSet($config);
    }

    /**
     * Emit a one-shot deprecation warning if the user still has a value in
     * `watchtower.cache.connection` (or the env var that feeds it). The
     * pre-rename code passed that value directly to `Redis::connection(...)`;
     * the post-rename code defers to Laravel's cache config and ignores it.
     * Without this warning, users who relied on a separate Redis connection
     * via `WATCHTOWER_REDIS_CONNECTION` would silently lose isolation and
     * only find out via traffic anomalies.
     */
    private function warnIfDeprecatedConnectionConfigSet(array $config): void
    {
        if (self::$deprecationWarningEmitted) {
            return;
        }

        $connection = $config['connection'] ?? null;

        if ($connection === null || $connection === '') {
            return;
        }

        self::$deprecationWarningEmitted = true;

        try {
            \Illuminate\Support\Facades\Log::channel(config('watchtower.log_channel', 'stack'))
                ->warning('Watchtower: `watchtower.cache.connection` (env: WATCHTOWER_REDIS_CONNECTION / GUARD_REDIS_CONNECTION) is deprecated and now ignored. The package defers to Laravel\'s cache config. To isolate Watchtower on a specific Redis connection, define a custom cache store in config/cache.php and set WATCHTOWER_CACHE_STORE to its name.', [
                    'configured_connection' => $connection,
                ]);
        } catch (\Throwable) {
            // Log channel resolution failure must not break service construction.
            // The warning is best-effort; users can still discover the change
            // via the CHANGELOG and config docblock.
        }
    }

    /**
     * Reset the static deprecation-warning flag. Test-only — lets each test
     * exercise the warning path independently.
     *
     * @internal
     */
    public static function resetDeprecationWarningFlag(): void
    {
        self::$deprecationWarningEmitted = false;
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

    private function ipKey(string $ip): string
    {
        return $this->keyPrefix.':ip:'.$ip;
    }

    /**
     * Check whether an already-normalized IP is currently blocked.
     * Pure cache read — no DB hit.
     */
    public function isBlocked(string $ip): bool
    {
        $value = $this->cache()->get($this->ipKey($ip));

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
     * Called after every block/unblock and after watchtower:sync.
     *
     * Clears stale entries by iterating the previous index, then writes
     * fresh per-IP keys and an updated index. If the DB read fails (e.g.
     * migration not run yet), the existing cache state is left intact —
     * we'd rather serve stale-but-correct entries than wipe everything.
     *
     * ⚠️ Atomicity caveat: rebuild is NOT atomic across the cache backend.
     * The sequence is (1) forget old per-IP keys, (2) write new per-IP
     * keys, (3) write new index. If the process is killed between steps —
     * or if the cache backend partially fails mid-iteration — the cache
     * can end up in an inconsistent state:
     *
     *   - Worst case: an IP unblocked in the DB but whose forget call
     *     failed remains in the cache as "yes blocked" until its TTL
     *     expires (default 24h). A legitimate user is locked out for
     *     that window.
     *   - The TTL safety net bounds the worst case; subsequent rebuilds
     *     read the new index (written last) and forget the right keys
     *     on the next pass.
     *
     * This trade-off is accepted for v1 because (a) rebuilds are fast
     * (sub-millisecond on Redis for typical blocklists), (b) crashes
     * mid-rebuild are rare, and (c) the alternative — a versioned key
     * prefix — adds an extra cache `get` to the request path. Revisit if
     * real-world reports show stale-entry issues; the migration path is
     * a versioned-prefix scheme that orphans old keys naturally via TTL.
     */
    public function rebuild(): void
    {
        try {
            $blocks = BlacklistedIp::active()->get(['ip', 'expires_at']);
        } catch (\Throwable $e) {
            \Illuminate\Support\Facades\Log::channel(config('watchtower.log_channel', 'stack'))
                ->warning('Watchtower: cache rebuild failed, keeping existing cache data', [
                    'error' => $e->getMessage(),
                ]);

            return;
        }

        $cache = $this->cache();

        // Forget the previous generation's per-IP keys so unblocked IPs
        // don't sit in the cache until their TTL expires.
        $oldIndex = (array) $cache->get($this->indexKey, []);
        foreach ($oldIndex as $oldIp) {
            $cache->forget($this->ipKey((string) $oldIp));
        }

        if ($blocks->isEmpty()) {
            $cache->forget($this->indexKey);

            return;
        }

        $newIndex = [];
        foreach ($blocks as $block) {
            $value = $block->expires_at
                ? $block->expires_at->toIso8601String()
                : '';

            $cache->put($this->ipKey($block->ip), $value, $this->ttlSeconds);
            $newIndex[] = $block->ip;
        }

        $cache->put($this->indexKey, $newIndex, $this->ttlSeconds);
    }

    /**
     * Warm the cache from DB on application boot if the index is missing
     * (e.g. fresh container, cache was flushed). No-op if the index is
     * already present — the per-IP entries are assumed valid until their
     * TTL expires or a block/unblock triggers a rebuild.
     *
     * Wrapped in try/catch because boot must never fail because of a cache
     * backend error. Examples: cache driver = database but the cache table
     * isn't migrated yet; Redis is down at boot time; DynamoDB is rate-
     * limiting. In all of those, we'd rather skip the warm-up and let the
     * first block/unblock trigger a rebuild than crash the whole app.
     * The failure surfaces via the configured log channel.
     */
    public function warmOnBoot(): void
    {
        try {
            if ($this->cache()->has($this->indexKey)) {
                return;
            }

            $this->rebuild();
        } catch (\Throwable $e) {
            \Illuminate\Support\Facades\Log::channel(config('watchtower.log_channel', 'stack'))
                ->warning('Watchtower: warmOnBoot failed, skipping cache warm-up', [
                    'error' => $e->getMessage(),
                ]);
        }
    }
}
