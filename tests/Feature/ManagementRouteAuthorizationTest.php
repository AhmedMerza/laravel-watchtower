<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Route;
use LogScope\Http\Middleware\Authorize as LogScopeAuthorize;
use LogScope\LogScope;
use Watchtower\Http\Middleware\Authorize;

afterEach(function () {
    LogScope::resetAuth();
});

it('uses LogScope\'s authorization instead of the Gate when LogScope is installed', function () {
    $middleware = Route::getRoutes()->getByName('watchtower.api.blocks')->gatherMiddleware();

    expect($middleware)->toContain(LogScopeAuthorize::class)
        ->not->toContain(Authorize::class);
});

it('needs nothing beyond LogScope\'s authorization', function () {
    LogScope::auth(fn () => true);

    // No viewWatchtower Gate is defined for this environment, so it would refuse.
    $this->getJson('/logscope/watchtower/api/blocks')->assertOk();
});
