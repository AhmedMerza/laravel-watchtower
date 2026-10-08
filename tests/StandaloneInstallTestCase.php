<?php

declare(strict_types=1);

namespace Watchtower\Tests;

/**
 * watchtower:install in an app without LogScope, where its output has to
 * tell the operator to define the `viewWatchtower` Gate.
 */
class StandaloneInstallTestCase extends InstallTestCase
{
    protected function getPackageProviders($app): array
    {
        return [StandaloneServiceProvider::class];
    }
}
