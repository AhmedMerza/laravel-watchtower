<?php

declare(strict_types=1);

namespace Watchtower\Console\Commands;

use Illuminate\Console\Command;
use Illuminate\Support\Facades\Log;
use Watchtower\Enums\BlockSource;
use Watchtower\Models\BlacklistedIp;
use Watchtower\Support\BlockScope;
use Watchtower\Support\BlockTargetRegistry;
use Watchtower\Targets\LaravelTarget;

class ReconcileCommand extends Command
{
    protected $signature = 'watchtower:reconcile';

    protected $description = 'Repair drift between the active blocklist and every enabled block target';

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
        //
        // Feed rows are left out too, as the live path leaves them out by
        // never announcing them (#21): thousands of ranges, re-imported
        // daily, are not something to mirror into Cloudflare's rule list.
        //
        // Lazy, so a long-lived blocklist is read in chunks rather than held
        // whole (#108). Every walk re-runs the query, so a target may walk it
        // more than once.
        $activeBlocks = BlacklistedIp::active()
            ->where('scope', BlockScope::GLOBAL)
            ->where('source', '!=', BlockSource::Feed)
            ->lazyById();

        $failed = 0;

        foreach ($targets as $name => $target) {
            try {
                $target->reconcile($activeBlocks);

                if (! $target instanceof LaravelTarget) {
                    $this->info("Reconciled {$name}.");

                    continue;
                }

                // Logged as well as printed: cron output is rarely read, and
                // the same count every run is the signal (#172).
                $pushed = $target->pushed();
                $this->info("Reconciled {$name}: {$pushed} pushed to master.");

                if ($pushed > 0) {
                    Log::channel(config('watchtower.log_channel', 'stack'))->warning(
                        'Watchtower: reconcile pushed blocks master was missing',
                        ['target' => $name, 'pushed' => $pushed]
                    );
                }
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
