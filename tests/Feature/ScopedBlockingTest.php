<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Route;
use Watchtower\Enums\BlockSource;
use Watchtower\Models\BlacklistedIp;
use Watchtower\Services\BlacklistCache;
use Watchtower\Support\BlockScope;

// These go through the real HTTP kernel: a scoped block is only worth
// anything if the route middleware actually stops the request.

beforeEach(function () {
    config()->set('cache.default', 'array');
    config()->set('watchtower.cache.store', 'array');
    config()->set('watchtower.scopes', ['auth']);
    Cache::flush();

    Route::get('/open', fn () => 'ok');
    Route::get('/login', fn () => 'ok')->middleware('watchtower:auth');
});

function blockScoped(string $ip, string $scope): void
{
    BlacklistedIp::create([
        'ip'         => $ip,
        'scope'      => $scope,
        'source'     => BlockSource::Manual,
        'source_env' => 'testing',
    ]);

    app(BlacklistCache::class)->rebuild();
}

it('blocks a scoped address on a route carrying the scope', function () {
    blockScoped('203.0.113.9', 'auth');

    $this->withServerVariables(['REMOTE_ADDR' => '203.0.113.9'])
        ->get('/login')
        ->assertForbidden();
});

it('lets the same address through every route that does not carry the scope', function () {
    blockScoped('203.0.113.9', 'auth');

    $this->withServerVariables(['REMOTE_ADDR' => '203.0.113.9'])
        ->get('/open')
        ->assertOk();
});

it('still blocks a global block everywhere, including scoped routes', function () {
    blockScoped('203.0.113.9', BlockScope::GLOBAL);

    $this->withServerVariables(['REMOTE_ADDR' => '203.0.113.9'])
        ->get('/open')
        ->assertForbidden();

    $this->withServerVariables(['REMOTE_ADDR' => '203.0.113.9'])
        ->get('/login')
        ->assertForbidden();
});

it('does not block an address scoped to a different scope', function () {
    config()->set('watchtower.scopes', ['auth', 'admin']);
    blockScoped('203.0.113.9', 'admin');

    $this->withServerVariables(['REMOTE_ADDR' => '203.0.113.9'])
        ->get('/login')
        ->assertOk();
});

it('lets a never_block address through a scoped route', function () {
    config()->set('watchtower.never_block', ['203.0.113.0/24']);
    blockScoped('203.0.113.9', 'auth');

    $this->withServerVariables(['REMOTE_ADDR' => '203.0.113.9'])
        ->get('/login')
        ->assertOk();
});

it('fails open on a scoped route when the cache store is unavailable', function () {
    blockScoped('203.0.113.9', 'auth');

    // A mistyped WATCHTOWER_CACHE_STORE: Cache::store() throws on every lookup.
    config()->set('watchtower.cache.store', 'does-not-exist');
    app()->forgetInstance(BlacklistCache::class);

    $this->withServerVariables(['REMOTE_ADDR' => '203.0.113.9'])
        ->get('/login')
        ->assertOk();
});

it('reads no database at all for a route naming an undeclared scope', function () {
    Route::get('/typo', fn () => 'ok')->middleware('watchtower:atuh');

    app(BlacklistCache::class)->rebuild();

    $queries = 0;
    DB::listen(function () use (&$queries) {
        $queries++;
    });

    foreach (range(1, 3) as $i) {
        $this->withServerVariables(['REMOTE_ADDR' => '203.0.113.9'])->get('/typo')->assertOk();
    }

    // An undeclared scope has no cache namespace, because rebuild() only
    // writes declared ones and block() refuses to store an undeclared scope.
    // Looking it up anyway would read the namespace as cold and warm it from
    // the DB — a full blocklist read on every request, from one typo in a
    // route file.
    expect($queries)->toBe(0);
});

it('lets requests through a route naming an undeclared scope', function () {
    config()->set('watchtower.scopes', ['auth']);
    blockScoped('203.0.113.9', 'auth');

    Route::get('/typo', fn () => 'ok')->middleware('watchtower:atuh');

    $this->withServerVariables(['REMOTE_ADDR' => '203.0.113.9'])
        ->get('/typo')
        ->assertOk();
});

it('reads no database when a declared scope has stray whitespace', function () {
    // BlockScope::declared() trims, so blocks store under 'auth'. If the
    // cache rebuild re-parsed the config without trimming, it would write the
    // namespace under 'auth ' instead, leaving the real one with no range key
    // — read as cold on every request, rebuilding the blocklist each time.
    config()->set('watchtower.scopes', ['auth ']);

    Route::get('/login-ws', fn () => 'ok')->middleware('watchtower:auth');

    app(BlacklistCache::class)->rebuild();

    $queries = 0;
    DB::listen(function () use (&$queries) {
        $queries++;
    });

    foreach (range(1, 3) as $i) {
        $this->withServerVariables(['REMOTE_ADDR' => '203.0.113.9'])->get('/login-ws')->assertOk();
    }

    expect($queries)->toBe(0);
});

it('blocks on a route naming several scopes when the address is blocked in either', function () {
    config()->set('watchtower.scopes', ['auth', 'admin']);
    Route::get('/panel', fn () => 'ok')->middleware('watchtower:auth,admin');

    blockScoped('203.0.113.9', 'admin');

    $this->withServerVariables(['REMOTE_ADDR' => '203.0.113.9'])
        ->get('/panel')
        ->assertForbidden();
});

it('lets an address through a multi-scope route when it is blocked in neither', function () {
    config()->set('watchtower.scopes', ['auth', 'admin']);
    Route::get('/panel', fn () => 'ok')->middleware('watchtower:auth,admin');

    $this->withServerVariables(['REMOTE_ADDR' => '203.0.113.9'])
        ->get('/panel')
        ->assertOk();
});
