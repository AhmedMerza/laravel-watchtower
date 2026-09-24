<?php

declare(strict_types=1);

namespace Watchtower\Console\Commands;

use Composer\InstalledVersions;
use Illuminate\Console\Command;
use Watchtower\Support\BlockScope;

class InstallCommand extends Command
{
    protected $signature = 'watchtower:install';

    protected $description = 'Install Watchtower: publish config and run migration';

    public function handle(): int
    {
        $this->info('Installing Watchtower...');

        $this->call('vendor:publish', ['--tag' => 'watchtower-config', '--force' => false]);
        $this->call('vendor:publish', ['--tag' => 'watchtower-migrations', '--force' => false]);
        $this->call('migrate');

        // Upgrade detection: a customised pre-rename config file at the old
        // path is now silently ignored by the package (which reads
        // config('watchtower.*')). Surface this so users don't lose tweaks.
        $oldConfigPath = function_exists('config_path')
            ? config_path('logscope-guard.php')
            : base_path('config/logscope-guard.php');

        if (file_exists($oldConfigPath)) {
            $this->newLine();
            $this->warn('⚠️  Found orphaned config file: '.$oldConfigPath);
            $this->line('   Watchtower now reads from <info>config/watchtower.php</info>. The old file is ignored.');
            $this->line('   Migrate any customisations into the new file, then delete the old one.');
        }

        $logscopeInstalled = class_exists('LogScope\\LogScope');

        $this->newLine();
        $this->info('✓ Watchtower installed!');
        $this->line('');
        $this->line('Add these to your <comment>.env</comment>:');
        $this->line('  <comment>WATCHTOWER_ENABLED=true</comment>');
        $this->line('  <comment>WATCHTOWER_NEVER_BLOCK_IPS=127.0.0.1,::1,your.ip.here</comment>');
        $this->line('  <comment>WATCHTOWER_MASTER_URL=https://master.example.com</comment>  (for cross-env sync)');
        $this->line('  <comment>WATCHTOWER_SYNC_SECRET=a-long-random-secret</comment>');
        $this->newLine();

        if ($logscopeInstalled) {
            $logscopePrefix = (string) config('logscope.routes.prefix', 'logscope');
            $this->line("LogScope detected — Watchtower routes mounted under <info>/{$logscopePrefix}/watchtower</info>");
            if ($this->logScopeEmbedsBlockButton()) {
                $this->line('Block-IP button has been added to your LogScope log detail panel.');
            } else {
                $this->line("LogScope 2.2+ has no Block-IP button — block from <info>/{$logscopePrefix}/watchtower</info> instead.");
            }
            $this->line('LogScope\'s own authorization guards those routes; Watchtower\'s <comment>routes.middleware</comment>');
            $this->line('and <comment>viewWatchtower</comment> Gate apply to standalone installs only and are inert here.');
        } else {
            $prefix = (string) config('watchtower.routes.prefix', 'watchtower');
            $this->line("Standalone mode — Watchtower routes mounted at <info>/{$prefix}</info>");
            $this->line('<comment>⚠️  Outside the local environment, the management routes refuse everyone until you</comment>');
            $this->line('<comment>   define the viewWatchtower Gate</comment>, e.g. in <info>AppServiceProvider::boot()</info>:');
            $this->line('   <info>Gate::define(\'viewWatchtower\', fn ($user) => $user->isAdmin());</info>');
            $this->line('   Set <info>WATCHTOWER_ROUTES_ENABLED=false</info> if you don\'t need the API.');
        }

        $this->reportScopes();

        return self::SUCCESS;
    }

    /**
     * Report each declared scope and whether any route actually carries it.
     *
     * A scoped block is inert until a route names its scope, and nothing at
     * runtime can tell "the middleware isn't wired up yet" from "that scope
     * name is a typo" — both just quietly enforce nothing. This is the one
     * place both are visible, so it is where they get said out loud.
     */
    private function reportScopes(): void
    {
        $scopes = BlockScope::declared();
        $covered = BlockScope::routeCounts();

        // The mirror mistake, and the one nothing else catches: a route names
        // a scope the config never declared, usually a typo. No block can be
        // stored in it, so the middleware is inert on that route.
        foreach (array_diff(array_keys($covered), $scopes) as $undeclared) {
            $this->newLine();
            $this->warn("⚠️  Routes name the scope '{$undeclared}', which config/watchtower.php doesn't declare.");
            $this->line("   Nothing can be blocked in it. Add it to <info>'scopes'</info>, or fix the route's middleware.");
        }

        if ($scopes === []) {
            return;
        }

        $this->newLine();
        $this->line('Block scopes declared in <info>config/watchtower.php</info>:');

        foreach ($scopes as $scope) {
            $routes = $covered[$scope] ?? 0;

            if ($routes > 0) {
                $this->line("  <info>✓</info> {$scope} — on {$routes} route(s)");

                continue;
            }

            $this->line("  <comment>⚠️  {$scope} — no route carries watchtower:{$scope}, so a block scoped to it does nothing</comment>");
            $this->line("     <info>Route::middleware('watchtower:{$scope}')->group(fn () => /* your routes */);</info>");
        }
    }

    /**
     * LogScope 1.6.1 to 2.1.x include our ip-actions partial in their log
     * detail panel; 2.2.0 stopped, deliberately (laravel-logscope 50d4adf),
     * so saying the button was added would send someone looking for it.
     *
     * A version that isn't a plain release — a dev branch — reads as the
     * newer behaviour, since that is where every branch is heading.
     */
    private function logScopeEmbedsBlockButton(): bool
    {
        $version = InstalledVersions::isInstalled('ahmedmerza/logscope')
            ? InstalledVersions::getVersion('ahmedmerza/logscope')
            : null;

        return $version !== null
            && preg_match('/^\d/', $version) === 1
            && version_compare($version, '2.2.0', '<');
    }
}
