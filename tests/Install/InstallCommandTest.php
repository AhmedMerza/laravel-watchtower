<?php

declare(strict_types=1);

use Illuminate\Routing\RouteCollection;
use Illuminate\Support\Facades\Schema;

it('installs cleanly against a genuinely fresh app, without a double-registered migration crash (#104)', function () {
    $this->artisan('watchtower:install')->assertSuccessful();

    expect(Schema::hasTable('blacklisted_ips'))->toBeTrue();
    expect(Schema::hasTable('ip_offences'))->toBeTrue();
    expect(Schema::hasColumn('blacklisted_ips', 'scope'))->toBeTrue();
});

it('runs a second time without error, as a repeated watchtower:install would', function () {
    $this->artisan('watchtower:install')->assertSuccessful();
    $this->artisan('watchtower:install')->assertSuccessful();
});

it('reports LogScope mode at the prefix the routes were actually mounted under (#51)', function () {
    $this->artisan('watchtower:install')
        ->expectsOutputToContain('LogScope detected — Watchtower routes mounted under /logscope/watchtower')
        ->doesntExpectOutputToContain("Gate::define('viewWatchtower'")
        ->doesntExpectOutputToContain('Standalone mode')
        ->assertSuccessful();
});

it('says the routes are off instead of naming a mode when none are registered (#51)', function () {
    // As WATCHTOWER_ROUTES_ENABLED=false or a route cache built before the
    // package was installed leave it: no watchtower route at all.
    app('router')->setRoutes(new RouteCollection);

    $this->artisan('watchtower:install')
        ->expectsOutputToContain("Watchtower's routes aren't registered")
        ->doesntExpectOutputToContain('LogScope detected')
        ->doesntExpectOutputToContain('Standalone mode')
        ->assertSuccessful();
});
