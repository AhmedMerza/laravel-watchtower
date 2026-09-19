<?php

declare(strict_types=1);

use Illuminate\Contracts\Http\Kernel;
use Watchtower\Http\Middleware\BlockedIpMiddleware;
use Watchtower\Http\Middleware\SignalDetectorMiddleware;

// Deliberately no $beforeBoot here: this file boots on the shipped defaults,
// which is the configuration almost every install actually runs.

it('leaves the detector middleware out of the stack on a stock install', function () {
    $middleware = app(Kernel::class)->getGlobalMiddleware();

    // "A request that matches nothing costs nothing extra" is cheapest to
    // honour by not being in the stack at all. Nothing else would catch a
    // regression that always registered it — the detectors' own per-request
    // `enabled` checks would still no-op, so no behaviour would change and
    // every other test would stay green while every request paid for a
    // middleware frame it never needed.
    expect($middleware)->toContain(BlockedIpMiddleware::class)
        ->and($middleware)->not->toContain(SignalDetectorMiddleware::class);
});

it('leaves it out when auto-block is on but no request detector is', function () {
    // The auth detectors are listeners, not middleware, so arming them must
    // not put the request middleware in the stack either.
    config()->set('watchtower.auto_block.enabled', true);
    config()->set('watchtower.auto_block.detectors.failed_logins.enabled', true);

    expect(app(Kernel::class)->getGlobalMiddleware())
        ->not->toContain(SignalDetectorMiddleware::class);
});
