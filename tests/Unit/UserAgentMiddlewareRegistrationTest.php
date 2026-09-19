<?php

declare(strict_types=1);

use Illuminate\Contracts\Http\Kernel;
use Watchtower\Http\Middleware\BlockedIpMiddleware;
use Watchtower\Http\Middleware\UserAgentMiddleware;

// Deliberately no $beforeBoot here: this file boots on the shipped defaults,
// which is the configuration almost every install actually runs. The
// switched-off case needs its own file, since registration happens at boot.

it('is in the stack on a stock install, after the blocking middleware', function () {
    $middleware = app(Kernel::class)->getGlobalMiddleware();

    // Unlike the detectors, this one ships on: it rejects a request rather
    // than blocking an address, so the cost of a false positive is a single
    // 403 the client sees immediately, not an hour-long lockout.
    expect($middleware)->toContain(UserAgentMiddleware::class);

    // After the blocking middleware, so an address that is already blocked
    // never reaches the User-Agent check.
    expect(array_search(UserAgentMiddleware::class, $middleware, true))
        ->toBeGreaterThan(array_search(BlockedIpMiddleware::class, $middleware, true));
});
