<?php

declare(strict_types=1);

namespace Watchtower\Tests;

/**
 * A master environment: sync routes are registered from config at boot, so
 * the secret has to be in place before the app comes up. Setting it in a
 * beforeEach() would be too late — the routes would already be absent.
 */
class SyncTestCase extends TestCase
{
    public function getEnvironmentSetUp($app): void
    {
        parent::getEnvironmentSetUp($app);

        config()->set('cache.default', 'array');
        config()->set('watchtower.cache.store', 'array');

        config()->set('watchtower.sync.master_url', 'https://master.example.com');
        config()->set('watchtower.sync.secret', 'test-secret');
        config()->set('watchtower.sync.timestamp_tolerance', 300);
    }
}
