<?php

declare(strict_types=1);

namespace Watchtower\Console\Commands;

use Illuminate\Console\Command;

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
            $this->line('Block-IP button has been added to your LogScope log detail panel.');
        } else {
            $prefix = (string) config('watchtower.routes.prefix', 'watchtower');
            $this->line("Standalone mode — Watchtower routes mounted at <info>/{$prefix}</info>");
            $this->line('<comment>⚠️  Until v1.0, the management routes have NO built-in authorization.</comment>');
            $this->line('   Wrap them in your own auth middleware via <info>config/watchtower.php</info> → <info>routes.middleware</info>,');
            $this->line('   or set <info>WATCHTOWER_ROUTES_ENABLED=false</info> if you don\'t need the UI yet.');
        }

        return self::SUCCESS;
    }
}
