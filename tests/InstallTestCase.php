<?php

declare(strict_types=1);

namespace Watchtower\Tests;

use Illuminate\Support\Facades\File;
use Illuminate\Support\ServiceProvider;
use Orchestra\Testbench\TestCase as Orchestra;
use Watchtower\WatchtowerServiceProvider;

/**
 * Deliberately does NOT extend TestCase: that base class pre-creates every
 * package table directly (raw ->up() calls) in getEnvironmentSetUp(), so
 * every other test starts with the schema already in place. Install tests
 * need the opposite — a genuinely empty app — because the thing under test
 * IS how the schema gets there (#104: publish + migrate double-registered
 * it when runsMigrations() was also loading the vendor copy).
 */
class InstallTestCase extends Orchestra
{
    protected function getPackageProviders($app): array
    {
        return [WatchtowerServiceProvider::class];
    }

    protected function setUp(): void
    {
        $this->resetPublishRegistry();

        parent::setUp();
    }

    /**
     * ServiceProvider::$publishes / $publishGroups are process-global
     * statics with no reset, keyed by the literal "from" path string.
     * StandaloneServiceProvider (tests/StandaloneServiceProvider.php)
     * extends WatchtowerServiceProvider without overriding
     * configurePackage(), so when a Standalone test boots earlier in the
     * same process, package-tools' getPackageBaseDir() reflects on ITS
     * file location and registers the same migrations again under a
     * different string key (tests/../database/migrations/... vs
     * src/../database/migrations/...) that never collides with the real
     * one. Both survive, so vendor:publish later copies each migration to
     * two destinations and migrate crashes — independent of #104's fix.
     * Clearing both registries before each install test keeps it
     * deterministic no matter what ran before it in the suite.
     */
    private function resetPublishRegistry(): void
    {
        foreach (['publishes', 'publishGroups'] as $property) {
            (new \ReflectionProperty(ServiceProvider::class, $property))->setValue(null, []);
        }
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
    }

    /**
     * vendor:publish writes real files into the testbench skeleton app's
     * database/migrations and config directories, which are shared across
     * every test run — unlike the in-memory sqlite connection, neither
     * resets itself. A stray published config is the worse of the two:
     * vendor:publish --force=false no-ops once it exists, and
     * mergeConfigFrom() only fills in keys ABSENT from it, so a key whose
     * default changed between versions would silently keep the stale value
     * for the whole run.
     */
    protected function tearDown(): void
    {
        foreach (File::glob(database_path('migrations/*_{create_blacklisted_ips_table,create_ip_offences_table,update_blacklisted_ips_table_add_scope}.php'), GLOB_BRACE) as $published) {
            File::delete($published);
        }

        File::delete(config_path('watchtower.php'));

        parent::tearDown();
    }
}
