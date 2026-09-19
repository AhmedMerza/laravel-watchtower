<?php

declare(strict_types=1);

namespace Watchtower\Services;

use Watchtower\Enums\BlockSource;
use Watchtower\Events\IpBlocked;
use Watchtower\Exceptions\NeverBlockException;
use Watchtower\Jobs\PushBlockToMaster;
use Watchtower\Models\BlacklistedIp;
use Watchtower\Support\IpRange;

class BlacklistService
{
    public function __construct(private readonly BlacklistCache $cache) {}

    /**
     * Block an IP or CIDR range. Normalizes the target, enforces the
     * never-block whitelist, writes to DB, rebuilds the cache, fires the
     * IpBlocked event, and dispatches a push job to the master environment
     * (if configured).
     *
     * A single IPv6 address is stored as its configured prefix
     * (`ipv6_block_prefix`, /64 by default), since the client can hop to
     * any other address inside it.
     *
     * If the rebuild can't read the DB, this block's entry is written
     * directly, since the middleware only reads the cache and would
     * otherwise let the IP through while every caller is told it was
     * blocked.
     *
     * @throws NeverBlockException when the never-block whitelist covers what was asked for
     */
    public function block(string $ip, array $options = []): BlacklistedIp
    {
        // Checked before widening: never_block protects the address asked
        // for. The rest of its /64 is still blocked, and the middleware
        // lets the whitelisted address through regardless.
        if ($this->isNeverBlock($ip)) {
            throw new NeverBlockException("{$this->normalizeIp($ip)} is in the never-block whitelist and cannot be blocked.");
        }

        $record = BlacklistedIp::updateOrCreate(
            ['ip' => $this->normalizeTarget($ip)],
            [
                'reason'       => $options['reason'] ?? null,
                'source_env'   => $options['source_env'] ?? app()->environment(),
                'source'       => $options['source'] ?? BlockSource::Manual,
                'expires_at'   => $options['expires_at'] ?? null,
                'blocked_by'   => $options['blocked_by'] ?? null,
                'log_entry_id' => $options['log_entry_id'] ?? null,
            ]
        );

        if (! $this->cache->rebuild()) {
            $this->cache->put($record);
        }

        event(new IpBlocked($record));

        if (config('watchtower.sync.master_url')) {
            PushBlockToMaster::dispatch($record)
                ->onQueue(config('watchtower.notifications.queue', 'default'));
        }

        return $record;
    }

    /**
     * Unblock an IP or range. Removes the DB record and rebuilds the cache.
     *
     * A single IP lifts its own row and the prefix row blocking it made, but
     * never a wider range that happens to cover it.
     *
     * Each target's entry is forgotten even when the rebuild succeeds: an
     * entry block() wrote after a failed rebuild isn't in the index, so no
     * rebuild will ever forget it.
     */
    public function unblock(string $ip): bool
    {
        $targets = $this->targetsFor($ip);
        $deleted = BlacklistedIp::whereIn('ip', $targets)->delete();

        foreach ($targets as $target) {
            $this->cache->forget($target);
        }

        $this->cache->rebuild();

        return $deleted > 0;
    }

    /**
     * The record blocking an IP or range: its own live row, else whichever
     * wider range covers it. An expired row of its own is the last resort,
     * so a lapsed block can still be reported.
     */
    public function find(string $ip): ?BlacklistedIp
    {
        $own = BlacklistedIp::whereIn('ip', $this->targetsFor($ip))->get();
        $record = $own->first(fn (BlacklistedIp $row) => ! $row->isExpired());

        if ($record !== null) {
            return $record;
        }

        $target = IpRange::canonical($ip);

        // Rows whose ip doesn't parse are skipped by covers().
        $covering = $target === null ? null : BlacklistedIp::active()
            ->where('ip', 'like', '%/%')
            ->get()
            ->first(fn (BlacklistedIp $range) => IpRange::covers([$range->ip], $target));

        return $covering ?? $own->first();
    }

    /**
     * Whether an IP or range is currently blocked, decided the way the
     * middleware decides it: never_block first, then the cache.
     *
     * A range has no single address to ask the cache about, so the row
     * blocking it answers instead.
     */
    public function isBlocked(string $ip): bool
    {
        // The middleware lets these through whatever covers them, so
        // reporting them as blocked would contradict what happens.
        if ($this->isNeverBlock($ip)) {
            return false;
        }

        if (str_contains($ip, '/')) {
            $record = $this->find($ip);

            return $record !== null && ! $record->isExpired();
        }

        return $this->cache->isBlocked($this->normalizeIp($ip));
    }

    /**
     * Normalize an IP address or range to its canonical form, e.g.
     * ::ffff:1.2.3.4 → 1.2.3.4, 10.1.2.3/8 → 10.0.0.0/8. Anything that
     * isn't an IP or range comes back unchanged.
     */
    public function normalizeIp(string $ip): string
    {
        return IpRange::canonical($ip) ?? $ip;
    }

    /**
     * What block() stores for $ip: normalizeIp(), with a single IPv6
     * address widened to the configured prefix.
     */
    public function normalizeTarget(string $ip): string
    {
        return IpRange::blockTarget($ip) ?? $ip;
    }

    /**
     * The rows that are this IP or range. A single IPv6 address has two: the
     * prefix block() stores, and the bare address an explicit /128, or a
     * block made before prefixes existed, left behind.
     *
     * @return list<string>
     */
    private function targetsFor(string $ip): array
    {
        return array_values(array_unique([$this->normalizeTarget($ip), $this->normalizeIp($ip)]));
    }

    private function isNeverBlock(string $ip): bool
    {
        $target = IpRange::canonical($ip);

        return $target !== null && IpRange::covers((array) config('watchtower.never_block', []), $target);
    }
}
