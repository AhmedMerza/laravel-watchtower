<?php

declare(strict_types=1);

namespace Watchtower\Tests;

use Closure;
use Illuminate\Database\Eloquent\Factories\Factory;
use Illuminate\Foundation\Application;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\File;
use Orchestra\Testbench\TestCase as Orchestra;
use Watchtower\Support\FailureWindow;
use Watchtower\WatchtowerServiceProvider;

class TestCase extends Orchestra
{
    /**
     * Runs against each new app before its providers boot, for a test file
     * that needs to observe booting. Set it in beforeAll(), clear it in
     * afterAll().
     *
     * @var (Closure(Application): void)|null
     */
    public static ?Closure $beforeBoot = null;

    protected function setUp(): void
    {
        parent::setUp();

        // Failure windows are marker files on disk, so they outlive the
        // app and would otherwise suppress logging in a later test.
        FailureWindow::forget('cache');
        FailureWindow::forget('warm');
        FailureWindow::forget('proxies');
        FailureWindow::forget('detector');
        FailureWindow::forget('scope');
        FailureWindow::forget('route_scope');
        FailureWindow::forget('escalation');
        FailureWindow::forget('escalation-ledger');
        FailureWindow::forget('rule-hold');

        Factory::guessFactoryNamesUsing(
            fn (string $modelName) => 'Watchtower\\Database\\Factories\\'.class_basename($modelName).'Factory'
        );
    }

    protected function getPackageProviders($app): array
    {
        return [WatchtowerServiceProvider::class];
    }

    public function getEnvironmentSetUp($app): void
    {
        config()->set('app.key', 'base64:'.base64_encode(random_bytes(32)));

        config()->set('database.default', 'testing');
        config()->set('database.connections.testing', [
            'driver'   => 'sqlite',
            'database' => ':memory:',
            'prefix'   => '',
        ]);

        // Run Guard migrations, sorted by file name — which is how Laravel's
        // migrator orders them, and therefore the only order that proves the
        // package installs cleanly. allFiles() returns filesystem order, which
        // hid a migration running before the one that creates its table.
        $migrations = collect(File::allFiles(__DIR__.'/../database/migrations'))
            ->sortBy(fn ($migration) => $migration->getFilename())
            ->values();

        foreach ($migrations as $migration) {
            (include $migration->getRealPath())->up();
        }

        // Create a minimal log_entries table so AutoBlockService tests can run
        // without requiring the full LogScope package to be installed.
        DB::statement('
            CREATE TABLE IF NOT EXISTS log_entries (
                id VARCHAR(26) PRIMARY KEY,
                level VARCHAR(20) NOT NULL,
                message TEXT NOT NULL,
                ip_address VARCHAR(50),
                -- Matches the LogScope column as of v1.8.0. It is being
                -- widened to a string upstream; the shared-IP guard counts
                -- distinct values and never does arithmetic on them, so
                -- either type works.
                user_id BIGINT,
                occurred_at DATETIME NOT NULL,
                created_at DATETIME,
                updated_at DATETIME
            )
        ');

        if (static::$beforeBoot) {
            (static::$beforeBoot)($app);
        }
    }
}
