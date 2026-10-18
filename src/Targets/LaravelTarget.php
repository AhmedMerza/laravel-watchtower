<?php

declare(strict_types=1);

namespace Watchtower\Targets;

use Watchtower\Contracts\BlockTarget;
use Watchtower\Enums\BlockSource;
use Watchtower\Enums\SyncRole;
use Watchtower\Jobs\PushBlockToMaster;
use Watchtower\Models\BlacklistedIp;
use Watchtower\Support\IpRange;
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
     * Walks $activeBlocks twice, so it must be re-iterable — ReconcileCommand
     * passes a LazyCollection, which re-runs its query.
     *
     * @param  iterable<BlacklistedIp>  $activeBlocks
     */
    public function reconcile(iterable $activeBlocks): void
    {
        $masterUrl = config('watchtower.sync.master_url');

        if (! $masterUrl || SyncRole::current() === SyncRole::Master) {
            return;
        }

        // Nothing of ours to repair, so no reason to ask master anything.
        // Only a peek: the records are walked again below rather than held,
        // since ReconcileCommand streams them (#108).
        $hasOurs = false;

        foreach ($activeBlocks as $record) {
            if ($record->source !== BlockSource::Sync) {
                $hasOurs = true;

                break;
            }
        }

        if (! $hasOurs) {
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
                // One malformed row must not stop every other repair. A row
                // with no usable ip can't match anything, so it's skipped;
                // an expiry that doesn't parse counts as already lapsed, so
                // ours gets pushed rather than trusted to a row we can't read.
                if (! is_array($block) || ! is_string($block['ip'] ?? null)) {
                    continue;
                }

                $expires = $block['expires_at'] ?? null;
                $onMaster[$block['ip']] = $expires === null ? null : (is_string($expires) ? (int) strtotime($expires) : 0);
            }
        }

        foreach ($activeBlocks as $record) {
            if ($record->source === BlockSource::Sync) {
                continue;
            }

            // Master keys a bare IPv6 address by the prefix block() widens it
            // to (applySync normalises every push), so an explicit /128 or a
            // pre-prefix row stored bare here would never match and be pushed
            // every run.
            $key = IpRange::blockTarget($record->ip) ?? $record->ip;

            if (! array_key_exists($key, $onMaster)) {
                $this->apply($record);

                continue;
            }

            $theirs = $onMaster[$key];

            if ($theirs !== null && ($record->expires_at === null || $record->expires_at->getTimestamp() > $theirs)) {
                $this->apply($record);
            }
        }
    }
}
