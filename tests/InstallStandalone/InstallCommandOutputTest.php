<?php

declare(strict_types=1);

use Illuminate\Routing\RouteCollection;
use Illuminate\Support\Facades\Route;
use Watchtower\Http\Middleware\Authorize;
use Watchtower\Tests\StandaloneServiceProvider;

it('tells a standalone install to define the viewWatchtower Gate, at the mounted prefix (#51)', function () {
    $this->artisan('watchtower:install')
        ->expectsOutputToContain('Standalone mode — Watchtower routes mounted at /watchtower')
        ->expectsOutputToContain("Gate::define('viewWatchtower', fn (\$user) => \$user->isAdmin());")
        ->doesntExpectOutputToContain('LogScope detected')
        ->assertSuccessful();
});

it('prints the prefix the routes were mounted at, not the one config holds now (#51)', function () {
    // Mounted at a slashed prefix, as a user might write it, then config moves
    // on: only an answer read off the route prints /ops/wt.
    config()->set('watchtower.routes.prefix', '/ops/wt/');
    app('router')->setRoutes(new RouteCollection);
    app()->getProvider(StandaloneServiceProvider::class)->reregisterRoutes();
    config()->set('watchtower.routes.prefix', 'watchtower');

    $this->artisan('watchtower:install')
        ->expectsOutputToContain('Standalone mode — Watchtower routes mounted at /ops/wt')
        ->doesntExpectOutputToContain('mounted at //')
        ->assertSuccessful();
});

it('finds the routes in an app that never refreshed its route name lookups (#51)', function () {
    // No routing provider ran refreshNameLookups(): the grouped route is still
    // indexed under the group's bare 'watchtower.api.' name.
    app('router')->setRoutes(new RouteCollection);
    Route::group(['prefix' => 'watchtower', 'middleware' => [Authorize::class], 'as' => 'watchtower.api.'], function () {
        Route::get('/api/blocks', fn () => null)->name('blocks');
    });

    $this->artisan('watchtower:install')
        ->expectsOutputToContain('Standalone mode — Watchtower routes mounted at /watchtower')
        ->doesntExpectOutputToContain("Watchtower's routes aren't registered")
        ->assertSuccessful();
});
