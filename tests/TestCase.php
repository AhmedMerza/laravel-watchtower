<?php

declare(strict_types=1);

namespace Watchtower\Tests;

use Illuminate\Database\Eloquent\Factories\Factory;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\File;
use Orchestra\Testbench\TestCase as Orchestra;
use Watchtower\WatchtowerServiceProvider;

class TestCase extends Orchestra
{
    protected function setUp(): void
    {
        parent::setUp();

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

        // Run Guard migration
        foreach (File::allFiles(__DIR__.'/../database/migrations') as $migration) {
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
                occurred_at DATETIME NOT NULL,
                created_at DATETIME,
                updated_at DATETIME
            )
        ');
    }
}
