<?php

declare(strict_types=1);

namespace Watchtower\Services;

use Watchtower\Enums\BlockSource;
use Watchtower\Events\IpBlocked;
use Watchtower\Jobs\PushBlockToMaster;
use Watchtower\Models\BlacklistedIp;

class BlacklistService
{
    public function __construct(private readonly BlacklistCache $cache) {}

    /**
     * Block an IP. Normalizes the IP, enforces the never-block whitelist,
     * writes to DB, rebuilds Redis, fires the IpBlocked event, and
     * dispatches a push job to the master environment (if configured).
     *
     * @throws \RuntimeException when the IP is in the never-block whitelist
     */
    public function block(string $ip, array $options = []): BlacklistedIp
    {
        $ip = $this->normalizeIp($ip);

        if ($this->isNeverBlock($ip)) {
            throw new \RuntimeException("IP {$ip} is in the never-block whitelist and cannot be blocked.");
        }

        $record = BlacklistedIp::updateOrCreate(
            ['ip' => $ip],
            [
                'reason'       => $options['reason'] ?? null,
                'source_env'   => $options['source_env'] ?? app()->environment(),
                'source'       => $options['source'] ?? BlockSource::Manual,
                'expires_at'   => $options['expires_at'] ?? null,
                'blocked_by'   => $options['blocked_by'] ?? null,
                'log_entry_id' => $options['log_entry_id'] ?? null,
            ]
        );

        $this->cache->rebuild();

        event(new IpBlocked($record));

        if (config('watchtower.sync.master_url')) {
            PushBlockToMaster::dispatch($record)
                ->onQueue(config('watchtower.notifications.queue', 'default'));
        }

        return $record;
    }

    /**
     * Unblock an IP. Removes the DB record and rebuilds Redis.
     */
    public function unblock(string $ip): bool
    {
        $ip = $this->normalizeIp($ip);
        $deleted = BlacklistedIp::where('ip', $ip)->delete();
        $this->cache->rebuild();

        return $deleted > 0;
    }

    /**
     * Check if an IP is currently blocked (delegates to Redis).
     */
    public function isBlocked(string $ip): bool
    {
        return $this->cache->isBlocked($this->normalizeIp($ip));
    }

    /**
     * Count currently-active blacklist entries (not yet expired),
     * for the summary shown on the status dashboard.
     */
    public function activeCount(): int
    {
        return BlacklistedIp::query()
            ->where('expires_at', '>', now())
            ->count();
    }

    /**
     * Normalize an IP address to its canonical form.
     * Handles IPv4-mapped IPv6 addresses (e.g. ::ffff:1.2.3.4 → 1.2.3.4).
     */
    public function normalizeIp(string $ip): string
    {
        $packed = @inet_pton($ip);

        if ($packed === false) {
            return $ip;
        }

        $normalized = inet_ntop($packed);

        // Unwrap IPv4-mapped IPv6
        if (str_starts_with($normalized, '::ffff:')) {
            $candidate = substr($normalized, 7);
            if (filter_var($candidate, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
                return $candidate;
            }
        }

        return $normalized;
    }

    private function isNeverBlock(string $ip): bool
    {
        return in_array($ip, config('watchtower.never_block', []), true);
    }
}
