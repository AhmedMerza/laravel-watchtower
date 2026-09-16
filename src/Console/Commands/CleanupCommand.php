<?php

declare(strict_types=1);

namespace Watchtower\Console\Commands;

use Illuminate\Console\Command;
use Watchtower\Models\BlacklistedIp;
use Watchtower\Services\BlacklistCache;

class CleanupCommand extends Command
{
    protected $signature = 'watchtower:cleanup';

    protected $description = 'Delete expired temporary blocks from the database and rebuild the Redis cache';

    public function __construct(private readonly BlacklistCache $cache)
    {
        parent::__construct();
    }

    public function handle(): int
    {
        $deleted = BlacklistedIp::whereNotNull('expires_at')
            ->where('expires_at', '<', now())
            ->delete();

        if ($deleted > 0) {
            // A failed rebuild here leaves IPs cached as blocked that the DB no
            // longer blocks, so a legitimate user stays locked out until the
            // cache entry hits its TTL. Cron has to see that.
            if (! $this->cache->rebuild()) {
                $this->error("Removed {$deleted} expired block(s), but the cache rebuild failed — they stay blocked in cache until their TTL expires.");

                return self::FAILURE;
            }

            $this->info("Removed {$deleted} expired block(s). Redis cache rebuilt.");
        } else {
            $this->info('Nothing to clean up — no expired blocks found.');
        }

        return self::SUCCESS;
    }
}
