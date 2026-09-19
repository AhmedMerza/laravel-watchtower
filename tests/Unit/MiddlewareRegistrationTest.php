<?php

declare(strict_types=1);

use Illuminate\Contracts\Http\Kernel;
use Illuminate\Http\Middleware\HandleCors;
use Illuminate\Http\Middleware\TrustProxies;
use Illuminate\Support\Facades\Log;
use Watchtower\Http\Middleware\BlockedIpMiddleware;
use Watchtower\Http\Middleware\UserAgentMiddleware;
use Watchtower\Support\FailureWindow;
use Watchtower\WatchtowerServiceProvider;

// The feature test covers the happy path — stock TrustProxies present, in a
// real HTTP kernel. These cover the branches it can't reach, because
// Testbench's stack always contains the stock TrustProxies.

/** An app's own subclass — the common Laravel pattern registerMiddleware() claims to match. */
class AppTrustProxies extends TrustProxies {}

/** Re-run the provider's registration against whatever is in the kernel now. */
function reRegister(): array
{
    $provider = new WatchtowerServiceProvider(app());

    Closure::bind(
        fn () => $this->registerMiddleware(),
        $provider,
        WatchtowerServiceProvider::class
    )();

    return app(Kernel::class)->getGlobalMiddleware();
}

it('splices the middleware directly after an app subclass of TrustProxies', function () {
    app(Kernel::class)->setGlobalMiddleware([HandleCors::class, AppTrustProxies::class]);

    expect(reRegister())->toBe([
        HandleCors::class,
        AppTrustProxies::class,
        BlockedIpMiddleware::class,
        UserAgentMiddleware::class,
    ]);
});

// Laravel types the global stack as class-strings, so this shouldn't happen —
// but if it ever did, an is_string() guard in front of the is_a() lookup would
// read the instance as "no TrustProxies here" and splice the block check in
// front of it, where it sees the proxy's IP instead of the client's.
it('finds an instantiated TrustProxies, rather than splicing in front of it', function () {
    $proxies = new AppTrustProxies;

    app(Kernel::class)->setGlobalMiddleware([HandleCors::class, $proxies]);

    expect(reRegister())->toBe([
        HandleCors::class,
        $proxies,
        BlockedIpMiddleware::class,
        UserAgentMiddleware::class,
    ]);
});

it('puts the middleware first when TrustProxies is absent from the global stack', function () {
    app(Kernel::class)->setGlobalMiddleware([HandleCors::class]);

    expect(reRegister())->toBe([
        BlockedIpMiddleware::class,
        UserAgentMiddleware::class,
        HandleCors::class,
    ]);
});

it('warns when TrustProxies is absent, because blocks will see the proxy IP', function () {
    app(Kernel::class)->setGlobalMiddleware([HandleCors::class]);

    Log::shouldReceive('channel')->andReturnSelf();
    Log::shouldReceive('warning')->once();

    reRegister();
});

it('stays silent when TrustProxies is present', function () {
    app(Kernel::class)->setGlobalMiddleware([TrustProxies::class]);

    Log::shouldReceive('channel')->andReturnSelf();
    Log::shouldReceive('warning')->never();

    reRegister();
});

it('does not register the middleware twice when registration runs again', function () {
    app(Kernel::class)->setGlobalMiddleware([TrustProxies::class]);

    reRegister();
    $middleware = reRegister();

    expect(array_keys($middleware, BlockedIpMiddleware::class, true))->toHaveCount(1);
});

afterEach(function () {
    FailureWindow::forget('proxies');
});
