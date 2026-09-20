<?php

declare(strict_types=1);

use Illuminate\Cache\Events\CacheHit;
use Illuminate\Cache\Events\CacheMissed;
use Illuminate\Support\Facades\Route;
use Watchtower\Enums\BlockSource;
use Watchtower\Models\BlacklistedIp;
use Watchtower\Services\BlacklistCache;
use Watchtower\Tests\TestCase;

// Under PHP-FPM the app boots for every request, so a cache read made while
// booting is paid per request too. The listener goes on before boot so it
// sees those.

beforeAll(function () {
    TestCase::$beforeBoot = function ($app) {
        $app['config']->set('cache.default', 'array');
        $app['config']->set('watchtower.cache.store', 'array');

        $reads = new ArrayObject;
        $app->instance('test.cache-reads', $reads);
        $app['events']->listen([CacheHit::class, CacheMissed::class], fn ($event) => $reads->append($event->key));
    };
});

afterAll(function () {
    TestCase::$beforeBoot = null;
});

it('reads the cache at most twice, boot included, for a request from an IP that is not blocked', function () {
    $reads = app('test.cache-reads');

    expect($reads->getArrayCopy())->toBe([]);

    Route::get('/watchtower-test', fn () => 'ok');

    foreach (['203.0.113.9', '198.18.0.0/16', '2001:db8:1:2::/64', '2001:db8:9::/48'] as $ip) {
        BlacklistedIp::create(['ip' => $ip, 'source' => BlockSource::Manual, 'source_env' => 'testing']);
    }

    app(BlacklistCache::class)->rebuild();
    $reads->exchangeArray([]);

    $this->withServerVariables(['REMOTE_ADDR' => '2001:db8:1:3::1'])
        ->get('/watchtower-test')
        ->assertOk();

    expect($reads->getArrayCopy())->toBe([
        'watchtower:blacklist:_ranges',
        'watchtower:blacklist:ip:2001:db8:1:3::/64',
    ]);
});

it('adds no cache reads to a route that carries no scope middleware', function () {
    $reads = app('test.cache-reads');

    config()->set('watchtower.scopes', ['auth']);

    Route::get('/watchtower-test', fn () => 'ok');

    // A scoped block exists and its namespace is warm. A route that does not
    // name the scope must still not pay for it — this is what makes scopes
    // free for the rest of the app, and it is the claim most likely to rot
    // if someone later moves the scope check into the global middleware.
    BlacklistedIp::create([
        'ip'         => '203.0.113.9',
        'scope'      => 'auth',
        'source'     => BlockSource::Manual,
        'source_env' => 'testing',
    ]);

    app(BlacklistCache::class)->rebuild();
    $reads->exchangeArray([]);

    $this->withServerVariables(['REMOTE_ADDR' => '203.0.113.9'])
        ->get('/watchtower-test')
        ->assertOk();

    expect($reads->getArrayCopy())->toBe([
        'watchtower:blacklist:_ranges',
        'watchtower:blacklist:ip:203.0.113.9',
    ]);
});

it('reads one extra pair of keys on a route that names a scope', function () {
    $reads = app('test.cache-reads');

    config()->set('watchtower.scopes', ['auth']);

    Route::get('/login', fn () => 'ok')->middleware('watchtower:auth');

    app(BlacklistCache::class)->rebuild();
    $reads->exchangeArray([]);

    $this->withServerVariables(['REMOTE_ADDR' => '203.0.113.9'])
        ->get('/login')
        ->assertOk();

    // The global pair first, from the global middleware, then the scope's
    // own pair. Four, not three: a scoped block can be a range, so the
    // lookup has the same shape as the global one.
    expect($reads->getArrayCopy())->toBe([
        'watchtower:blacklist:_ranges',
        'watchtower:blacklist:ip:203.0.113.9',
        'watchtower:blacklist:s:auth:_ranges',
        'watchtower:blacklist:s:auth:ip:203.0.113.9',
    ]);
});

it('adds no cache operations for a User-Agent the filter does not match', function () {
    $reads = app('test.cache-reads');

    Route::get('/watchtower-test', fn () => 'ok');

    app(BlacklistCache::class)->rebuild();
    $reads->exchangeArray([]);

    $this->withServerVariables(['REMOTE_ADDR' => '203.0.113.9'])
        ->withHeaders(['User-Agent' => 'curl/8.5.0'])
        ->get('/watchtower-test')
        ->assertOk();

    // The User-Agent filter ships enabled, so it is in the stack for this
    // request. Matching is one regex against a literal alternation and
    // nothing else: the two reads below are the block check's, exactly as
    // they are without the filter.
    expect($reads->getArrayCopy())->toBe([
        'watchtower:blacklist:_ranges',
        'watchtower:blacklist:ip:203.0.113.9',
    ]);
});
