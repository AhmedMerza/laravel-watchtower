<?php

declare(strict_types=1);

namespace Watchtower\Tests;

use Watchtower\WatchtowerServiceProvider;

/**
 * The provider as it boots in an app without LogScope. LogScope is a dev
 * dependency here, so class detection alone always picks LogScope mode.
 */
class StandaloneServiceProvider extends WatchtowerServiceProvider
{
    protected function logScopeAuthorizeMiddleware(): ?string
    {
        return null;
    }

    /** Re-run route registration after a test changes routes config. */
    public function reregisterRoutes(): void
    {
        $this->registerRoutes();

        // Route names are applied after the route is added, so the lookup
        // still points at the old route until it's rebuilt, as boot does.
        $this->app['router']->getRoutes()->refreshNameLookups();
    }

    /** Re-run the default Gate definition, as a provider booting late would. */
    public function redefineGate(): void
    {
        $this->defineGate();
    }
}
