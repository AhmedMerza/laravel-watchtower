<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Route;
use Watchtower\Enums\BlockSource;
use Watchtower\Models\BlacklistedIp;
use Watchtower\Services\BlacklistCache;
use Watchtower\Tests\TestCase;

// The `watchtower` route-middleware alias is registered at BOOT, before the
// enabled check. Turning Watchtower off with config()->set() inside a test
// happens long after the provider has already registered it, so the assertion
// below would pass however the provider was written. It has to be off before
// the app comes up, which is what $beforeBoot does and a beforeEach() cannot.
beforeAll(function () {
    TestCase::$beforeBoot = function ($app) {
        $app['config']->set('cache.default', 'array');
        $app['config']->set('watchtower.cache.store', 'array');
        $app['config']->set('watchtower.scopes', ['auth']);
        $app['config']->set('watchtower.enabled', false);
    };
});

afterAll(function () {
    TestCase::$beforeBoot = null;
});

beforeEach(function () {
    Cache::flush();

    Route::get('/login', fn () => 'ok')->middleware('watchtower:auth');
});

it('still resolves routes naming the alias when watchtower is disabled', function () {
    // WATCHTOWER_ENABLED=false is the switch you reach for when something is
    // wrong. If the alias were registered behind that check, throwing it
    // would raise "Middleware [watchtower] not found" on every route that
    // names a scope — the off switch would be the thing that breaks the site.
    BlacklistedIp::create([
        'ip'         => '203.0.113.9',
        'scope'      => 'auth',
        'source'     => BlockSource::Manual,
        'source_env' => 'testing',
    ]);
    app(BlacklistCache::class)->rebuild();

    $this->withServerVariables(['REMOTE_ADDR' => '203.0.113.9'])
        ->get('/login')
        ->assertOk();
});
