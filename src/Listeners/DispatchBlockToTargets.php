<?php

declare(strict_types=1);

namespace Watchtower\Listeners;

use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Support\Facades\Log;
use Watchtower\Events\IpBlocked;
use Watchtower\Support\BlockScope;
use Watchtower\Support\BlockTargetRegistry;

class DispatchBlockToTargets implements ShouldQueue
{
    public function __construct(private readonly BlockTargetRegistry $registry) {}

    public function handle(IpBlocked $event): void
    {
        // Checked once, here, for every target — not inside each one. An
        // edge/infrastructure target has no way to enforce "only these
        // routes"; pushing a scoped block there would block more than was
        // asked for. The `laravel` target needs this just as much, for a
        // narrower reason: the sync wire format carries no scope field, so a
        // scoped block pushed to master would be stored there as global and
        // handed to every satellite as an app-wide block nobody asked for
        // (#133 would widen the wire format; until then this is the only guard).
        // This repo has already paid twice (#38, and twice again inside
        // #27's own review) for the same guard duplicated per call site and
        // left to drift, so it lives in exactly one place.
        if ($event->record->scope !== BlockScope::GLOBAL) {
            return;
        }

        foreach ($this->registry->enabled() as $name => $target) {
            try {
                $target->apply($event->record);
            } catch (\Throwable $e) {
                // One target's failure must not stop the others (#25's AC).
                // Recovery is watchtower:reconcile, not a queue retry — a
                // retry here would redo every target's already-successful
                // apply() just to catch the one that failed.
                Log::channel(config('watchtower.log_channel', 'stack'))->warning(
                    "Watchtower: block target [{$name}] failed to apply",
                    ['ip' => $event->record->ip, 'error' => $e->getMessage()]
                );
            }
        }
    }
}
