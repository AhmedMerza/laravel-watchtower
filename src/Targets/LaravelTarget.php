<?php

declare(strict_types=1);

namespace Watchtower\Targets;

use Illuminate\Support\Carbon;
use Watchtower\Contracts\BlockTarget;
use Watchtower\Enums\BlockSource;
use Watchtower\Enums\SyncRole;
use Watchtower\Jobs\PushBlockToMaster;
use Watchtower\Models\BlacklistedIp;
use Watchtower\Support\MasterBlocks;
use Watchtower\Support\SyncSignature;

/**
 * Today's master/satellite sync, exposed through the BlockTarget contract.
 * Not new behaviour: apply() is exactly what BlacklistService::block() used
 * to dispatch inline, just relocated so it runs alongside any other enabled
 * target instead of being sync's own special case.
 */
class LaravelTarget implements BlockTarget
{
    public function apply(BlacklistedIp $record): void
    {
        // PushBlockToMaster::handle() already refuses a Sync record, a
        // missing master_url and the master itself once dispatched — checked again here so
        // reconcile() (which walks every active record, Sync-sourced ones
        // included on a satellite) never pays for a queue round trip whose
        // job would just return.
        if ($record->source === BlockSource::Sync) {
            return;
        }

        if (! config('watchtower.sync.master_url') || SyncRole::current() === SyncRole::Master) {
            return;
        }

        PushBlockToMaster::dispatch($record)
            ->onQueue(config('watchtower.sync.queue', 'default'));
    }

    /**
     * No push-based unblock exists today — a satellite only learns about an
     * unblock from its own scheduled watchtower:sync pull. #25 doesn't ask
     * for a new propagation mechanism, so this exists only to satisfy the
     * contract.
     */
    public function remove(string $ip): void
    {
        // Intentional no-op.
    }

    /**
     * Re-push the blocks master is missing. Nothing else retries a push whose
     * job exhausted PushBlockToMaster's 3 tries — this is that retry, run
     * whenever `watchtower:reconcile` is invoked.
     *
     * It used to re-push every active block, one queue job each, every run —
     * job volume grew with the whole blocklist rather than with drift (#108).
     * Now it reads master's list first and pushes only what master doesn't
     * hold, or holds with an earlier expiry than ours (a lost escalation).
     * Master holding it longer, or forever, has nothing to repair.
     *
     * @param  iterable<BlacklistedIp>  $activeBlocks
     */
    public function reconcile(iterable $activeBlocks): void
    {
        $masterUrl = config('watchtower.sync.master_url');

        if (! $masterUrl || SyncRole::current() === SyncRole::Master) {
            return;
        }

        $ours = [];

        foreach ($activeBlocks as $record) {
            if ($record->source !== BlockSource::Sync) {
                $ours[] = $record;
            }
        }

        // Nothing of ours to repair, so no reason to ask master anything.
        if ($ours === []) {
            return;
        }

        $secret = SyncSignature::secret();

        // apply() would queue jobs that refuse to send unsigned; reconcile
        // can't even read master's list, and cron should hear about it.
        if ($secret === '') {
            throw new \RuntimeException('WATCHTOWER_MASTER_URL is set but WATCHTOWER_SYNC_SECRET is not, so master\'s blocklist cannot be read.');
        }

        // ip => expiry timestamp, null for permanent.
        $onMaster = [];

        foreach (MasterBlocks::pages((string) $masterUrl, $secret) as $blocks) {
            foreach ($blocks as $block) {
                $onMaster[$block['ip']] = isset($block['expires_at']) ? Carbon::parse($block['expires_at'])->getTimestamp() : null;
            }
        }

        foreach ($ours as $record) {
            if (! array_key_exists($record->ip, $onMaster)) {
                $this->apply($record);

                continue;
            }

            $theirs = $onMaster[$record->ip];

            if ($theirs !== null && ($record->expires_at === null || $record->expires_at->getTimestamp() > $theirs)) {
                $this->apply($record);
            }
        }
    }
}
