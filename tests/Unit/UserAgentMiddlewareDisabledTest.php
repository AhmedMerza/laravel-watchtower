<?php

declare(strict_types=1);

use Illuminate\Contracts\Http\Kernel;
use Watchtower\Http\Middleware\BlockedIpMiddleware;
use Watchtower\Http\Middleware\UserAgentMiddleware;
use Watchtower\Tests\TestCase;

// Registration is decided at boot, so switching the filter off has to happen
// before the app comes up — which is what $beforeBoot does and a beforeEach()
// cannot. Hence a file of its own.

beforeAll(function () {
    TestCase::$beforeBoot = function ($app) {
        $app['config']->set('watchtower.user_agents.enabled', false);
    };
});

afterAll(function () {
    TestCase::$beforeBoot = null;
});

it('leaves the User-Agent middleware out of the stack entirely', function () {
    // Switching it off has to mean no stack frame, not a frame that no-ops:
    // nothing else would catch a regression that always registered it, since
    // the middleware's own per-request check would keep every other test
    // green while every request paid for a frame it never needed.
    $middleware = app(Kernel::class)->getGlobalMiddleware();

    expect($middleware)->toContain(BlockedIpMiddleware::class)
        ->and($middleware)->not->toContain(UserAgentMiddleware::class);
});
