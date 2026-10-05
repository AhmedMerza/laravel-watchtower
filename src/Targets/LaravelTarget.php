<?php

declare(strict_types=1);

namespace Watchtower\Targets;

use Watchtower\Contracts\BlockTarget;
use Watchtower\Enums\BlockSource;
use Watchtower\Enums\SyncRole;
use Watchtower\Jobs\PushBlockToMaster;
use Watchtower\Models\BlacklistedIp;

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
     * Re-push every active global block to master. Nothing today retries a
     * push whose job exhausted PushBlockToMaster's 3 tries — this is that
     * retry, run whenever `watchtower:reconcile` is invoked.
     *
     * @param  iterable<BlacklistedIp>  $activeBlocks
     */
    public function reconcile(iterable $activeBlocks): void
    {
        foreach ($activeBlocks as $record) {
            $this->apply($record);
        }
    }
}
