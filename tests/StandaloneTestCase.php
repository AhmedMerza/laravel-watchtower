<?php

declare(strict_types=1);

namespace Watchtower\Tests;

/**
 * An app without LogScope: the management API mounts at Watchtower's own
 * prefix, behind the `viewWatchtower` Gate.
 */
class StandaloneTestCase extends TestCase
{
    protected function getPackageProviders($app): array
    {
        return [StandaloneServiceProvider::class];
    }

    public function getEnvironmentSetUp($app): void
    {
        parent::getEnvironmentSetUp($app);

        config()->set('cache.default', 'array');
        config()->set('watchtower.cache.store', 'array');
    }
}
