<?php

declare(strict_types=1);

use Illuminate\Http\Middleware\TrustProxies;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Route;
use Watchtower\Enums\BlockSource;
use Watchtower\Models\BlacklistedIp;
use Watchtower\Services\BlacklistCache;

// These go through the real HTTP kernel, so they exercise where the
// middleware sits in the global stack, not just what it does.

beforeEach(function () {
    config()->set('cache.default', 'array');
    config()->set('watchtower.cache.store', 'array');
    Cache::flush();

    // Symfony keeps trusted proxies in a static, so an earlier test's
    // TrustProxies run would otherwise leak in and mask the ordering bug.
    Request::setTrustedProxies([], Request::HEADER_X_FORWARDED_FOR);

    Route::get('/watchtower-test', fn () => 'ok');

    BlacklistedIp::create([
        'ip'         => '203.0.113.9',
        'source'     => BlockSource::Manual,
        'source_env' => 'testing',
    ]);
    app(BlacklistCache::class)->rebuild();
});

it('blocks a forwarded client IP arriving through a trusted proxy', function () {
    TrustProxies::at('10.0.0.1');

    $this->withServerVariables(['REMOTE_ADDR' => '10.0.0.1'])
        ->get('/watchtower-test', ['X-Forwarded-For' => '203.0.113.9'])
        ->assertForbidden();
});

it('lets a non-blocked forwarded client IP through the same proxy', function () {
    TrustProxies::at('10.0.0.1');

    $this->withServerVariables(['REMOTE_ADDR' => '10.0.0.1'])
        ->get('/watchtower-test', ['X-Forwarded-For' => '198.51.100.7'])
        ->assertOk();
});

it('lets requests through when the cache store is unavailable', function () {
    // A mistyped WATCHTOWER_CACHE_STORE: Cache::store() throws on every lookup.
    config()->set('watchtower.cache.store', 'does-not-exist');
    app()->forgetInstance(BlacklistCache::class);

    $this->withServerVariables(['REMOTE_ADDR' => '203.0.113.9'])
        ->get('/watchtower-test')
        ->assertOk()
        ->assertSee('ok');
});
