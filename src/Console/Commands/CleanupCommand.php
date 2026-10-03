<?php

declare(strict_types=1);

namespace Watchtower\Console\Commands;

use Illuminate\Console\Command;
use Watchtower\Events\IpUnblocked;
use Watchtower\Models\BlacklistedIp;
use Watchtower\Services\BlacklistCache;
use Watchtower\Services\OffenceLedger;
use Watchtower\Support\BlockScope;

class CleanupCommand extends Command
{
    protected $signature = 'watchtower:cleanup';

    protected $description = 'Delete expired temporary blocks from the database and rebuild the Redis cache';

    public function __construct(
        private readonly BlacklistCache $cache,
        private readonly OffenceLedger $offences,
    ) {
        parent::__construct();
    }

    public function handle(): int
    {
        // Before the blocks, so that a failed cache rebuild below — which
        // returns early — doesn't leave spent ledger rows accumulating for
        // as long as the cache stays broken. Nothing here touches the cache.
        //
        // Caught for the same reason the ledger is caught where a block is
        // decided: this is housekeeping for an optional feature that is off
        // by default, and it must not cost the expired-block deletion and
        // cache rebuild below, which are what this command is actually for.
        // Running first would otherwise mean a broken ledger table stops
        // blocks from ever lapsing.
        try {
            $pruned = $this->offences->prune();
        } catch (\Throwable $e) {
            $pruned = 0;
            $this->warn('Could not prune the offence ledgers, carrying on with the blocks: '.$e->getMessage());
        }

        if ($pruned > 0) {
            $this->info("Forgot {$pruned} decayed offence ledger(s).");
        }

        // Fetched before the bulk delete below: this is the OTHER path a
        // blacklisted_ips row disappears by (BlacklistService::remove() is
        // the other), and it's a raw query rather than a remove() call per
        // row for the same reason remove() itself batches its cache work —
        // cleanup can lapse many rows at once and a per-row rebuild would
        // multiply that cost by however many expired. IpUnblocked still has
        // to fire for each GLOBAL one, or a future BlockTarget (cloudflare,
        // nginx_file) never learns a temporary block lapsed and keeps
        // enforcing it at the edge until the next watchtower:reconcile.
        $expiring = BlacklistedIp::whereNotNull('expires_at')
            ->where('expires_at', '<', now())
            ->get();

        $deleted = BlacklistedIp::whereNotNull('expires_at')
            ->where('expires_at', '<', now())
            ->delete();

        foreach ($expiring as $record) {
            if ($record->scope === BlockScope::GLOBAL) {
                event(new IpUnblocked($record->ip));
            }
        }

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
