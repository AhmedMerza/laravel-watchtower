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

describe('ranges', function () {
    beforeEach(function () {
        foreach (['198.18.0.0/16', '2001:db8:1:2::/64'] as $ip) {
            BlacklistedIp::create(['ip' => $ip, 'source' => BlockSource::Manual, 'source_env' => 'testing']);
        }

        app(BlacklistCache::class)->rebuild();
    });

    it('rejects a client inside a blocked range and lets one outside through', function (string $inside, string $outside) {
        $this->withServerVariables(['REMOTE_ADDR' => $inside])->get('/watchtower-test')->assertForbidden();
        $this->withServerVariables(['REMOTE_ADDR' => $outside])->get('/watchtower-test')->assertOk();
    })->with([
        'IPv4' => ['198.18.200.1', '198.19.0.1'],
        'IPv6' => ['2001:db8:1:2:dead:beef::1', '2001:db8:1:3::1'],
    ]);

    it('lets a client through when a never-block range covers it', function (string $neverBlock, string $client) {
        config()->set('watchtower.never_block', [$neverBlock]);

        $this->withServerVariables(['REMOTE_ADDR' => $client])->get('/watchtower-test')->assertOk();
    })->with([
        'IPv4 range'   => ['198.18.5.0/24', '198.18.5.9'],
        'IPv6 range'   => ['2001:db8:1:2::/64', '2001:db8:1:2::9'],
        'IPv6 address' => ['2001:DB8:1:2::9', '2001:db8:1:2::9'],
    ]);

    it('keeps blocking when a never-block entry is malformed', function () {
        // IpUtils does arithmetic on the prefix, so this reached it as a PHP
        // warning, which Laravel throws — on every request.
        config()->set('watchtower.never_block', ['198.18.0.0/1a', 'not-an-ip', '']);

        $this->withServerVariables(['REMOTE_ADDR' => '198.18.0.1'])->get('/watchtower-test')->assertForbidden();
        $this->withServerVariables(['REMOTE_ADDR' => '198.19.0.1'])->get('/watchtower-test')->assertOk();
    });
});
