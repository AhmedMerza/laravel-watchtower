<?php

declare(strict_types=1);

namespace Watchtower\Listeners;

use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Support\Facades\Log;
use Watchtower\Events\IpUnblocked;
use Watchtower\Support\BlockTargetRegistry;

class DispatchUnblockToTargets implements ShouldQueue
{
    public function __construct(private readonly BlockTargetRegistry $registry) {}

    public function handle(IpUnblocked $event): void
    {
        // No scope check here: IpUnblocked only fires when the global block
        // was among what got cleared (see BlacklistService::remove()), so by
        // construction every event that reaches this listener means the
        // global block is gone.
        foreach ($this->registry->enabled() as $name => $target) {
            try {
                $target->remove($event->ip);
            } catch (\Throwable $e) {
                Log::channel(config('watchtower.log_channel', 'stack'))->warning(
                    "Watchtower: block target [{$name}] failed to remove",
                    ['ip' => $event->ip, 'error' => $e->getMessage()]
                );
            }
        }
    }
}
