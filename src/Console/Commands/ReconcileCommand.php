<?php

declare(strict_types=1);

namespace Watchtower\Console\Commands;

use Illuminate\Console\Command;
use Illuminate\Support\Facades\Log;
use Watchtower\Models\BlacklistedIp;
use Watchtower\Support\BlockScope;
use Watchtower\Support\BlockTargetRegistry;

class ReconcileCommand extends Command
{
    protected $signature = 'watchtower:reconcile';

    protected $description = 'Push the full active blocklist to every enabled block target, to repair drift';

    public function __construct(private readonly BlockTargetRegistry $registry)
    {
        parent::__construct();
    }

    public function handle(): int
    {
        $targets = $this->registry->enabled();

        if ($targets === []) {
            $this->info('No block targets enabled.');

            return self::SUCCESS;
        }

        // Scoped blocks never reach a target (see DispatchBlockToTargets):
        // an edge/infrastructure target has no route to enforce "only these
        // paths" against, so reconcile walks the same GLOBAL-only set the
        // live path does.
        $activeBlocks = BlacklistedIp::active()->where('scope', BlockScope::GLOBAL)->get();

        $failed = 0;

        foreach ($targets as $name => $target) {
            try {
                $target->reconcile($activeBlocks);
                $this->info("Reconciled {$name}.");
            } catch (\Throwable $e) {
                $failed++;
                $this->error("Failed to reconcile {$name}: {$e->getMessage()}");
                Log::channel(config('watchtower.log_channel', 'stack'))->error(
                    "Watchtower: reconcile failed for target [{$name}]",
                    ['error' => $e->getMessage()]
                );
            }
        }

        return $failed > 0 ? self::FAILURE : self::SUCCESS;
    }
}
