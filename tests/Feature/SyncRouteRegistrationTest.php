<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Route;
use Watchtower\Support\SyncSignature;
use Watchtower\WatchtowerServiceProvider;

// No sync secret is configured in the base TestCase, so the app boots as an
// environment that should expose nothing.

it('registers no sync routes without a shared secret', function () {
    expect(Route::has('watchtower.sync.blocks'))->toBeFalse()
        ->and(Route::has('watchtower.sync.receive'))->toBeFalse();
});

it('404s the sync paths without a shared secret', function () {
    $this->getJson(SyncSignature::PULL_PATH)->assertNotFound();
    $this->postJson(SyncSignature::PUSH_PATH, ['ip' => '1.2.3.4'])->assertNotFound();
});

// The routes are registered at boot, so these run the registration again
// with the role in place rather than rebooting the app.
function registerSyncRoutesWith(?string $role): bool
{
    config()->set('watchtower.sync.secret', 'test-secret');
    config()->set('watchtower.sync.role', $role);

    $provider = app()->getProvider(WatchtowerServiceProvider::class);
    (fn () => $this->registerSyncRoutes())->call($provider);
    app('router')->getRoutes()->refreshNameLookups();

    return Route::has('watchtower.sync.blocks') && Route::has('watchtower.sync.receive');
}

it('serves the sync routes on the master', function () {
    expect(registerSyncRoutesWith('master'))->toBeTrue();
});

it('serves the sync routes with no role, as before #36', function () {
    expect(registerSyncRoutesWith(null))->toBeTrue();
});

it('serves nothing on a satellite, though it holds the secret', function () {
    expect(registerSyncRoutesWith('satellite'))->toBeFalse();
});

it('serves nothing when the role is unrecognised', function () {
    expect(registerSyncRoutesWith(' Sattelite '))->toBeFalse();
});

it('reads the role case-insensitively', function () {
    expect(registerSyncRoutesWith(' Master '))->toBeTrue();
});
