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

        // Caught for the same reason prune() above is: this is housekeeping
        // for the hits/last_hit_at columns, and a transient cache or DB
        // fault partway through it must not abort the expired-block
        // deletion and cache rebuild below, which are what this command is
        // actually for.
        try {
            $this->flushHits();
        } catch (\Throwable $e) {
            $this->warn('Could not flush hit counts, carrying on with the blocks: '.$e->getMessage());
        }

        // Fetched before the bulk delete below: this is the OTHER path a
        // blacklisted_ips row disappears by (BlacklistService::remove() is
        // the other), and it's a raw query rather than a remove() call per
        // row for the same reason remove() itself batches its cache work —
        // cleanup can lapse many rows at once and a per-row rebuild would
        // multiply that cost by however many expired. IpUnblocked still has
        // to fire for each GLOBAL one, or an enabled BlockTarget (cloudflare,
        // nginx_file) never learns a temporary block lapsed and keeps
        // enforcing it at the edge until the next watchtower:reconcile.
        //
        // $now is captured ONCE and reused in both queries below: now()
        // returns a fresh, later timestamp on each call, and a row whose
        // expires_at falls between two separate calls would be deleted
        // without ever appearing in $expiring — so it's deleted but the
        // event that tells a target it lapsed never fires. /mr-review
        // caught this (PR #107); only ip/scope are selected since that's
        // all the loop below reads.
        $now = now();

        $expiring = BlacklistedIp::whereNotNull('expires_at')
            ->where('expires_at', '<', $now)
            ->get(['ip', 'scope']);

        $deleted = BlacklistedIp::whereNotNull('expires_at')
            ->where('expires_at', '<', $now)
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

    /**
     * Move every block's pending cache hit count into its `hits` and
     * `last_hit_at` columns.
     *
     * Runs before the expired-block deletion above so a block that took a
     * last hit just before lapsing still gets that hit recorded, even though
     * the row disappears moments later anyway.
     *
     * Chunked rather than one `all()`: unlike the expired-block query above,
     * this reads every row in the table, including every permanent block
     * that will never be deleted — so it grows with the table's lifetime
     * total, not with how much is currently active, and needs a bound on
     * memory independent of how large that gets.
     */
    private function flushHits(): void
    {
        $flushed = 0;

        BlacklistedIp::query()
            ->select(['id', 'ip', 'scope', 'hits'])
            ->chunkById(500, function ($blocks) use (&$flushed) {
                // One cache read per chunk, not per row: a feed import makes
                // this thousands of rows, nearly all with nothing pending.
                foreach ($this->cache->pullHitsFor($blocks) as $position => $hits) {
                    $blocks[$position]->increment('hits', $hits, ['last_hit_at' => now()]);
                    $flushed++;
                }
            });

        if ($flushed > 0) {
            $this->info("Flushed hit counts for {$flushed} block(s).");
        }
    }
}
