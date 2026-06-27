<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Schema;
use Watchtower\Enums\BlockSource;
use Watchtower\Models\BlacklistedIp;
use Watchtower\Services\BlacklistCache;

beforeEach(function () {
    // Use the array cache store — a real cache, no mocking. Each test gets
    // a fresh store via Cache::flush() so state doesn't leak between tests.
    config()->set('cache.default', 'array');
    config()->set('watchtower.cache', [
        'store'     => 'array',
        'key'       => 'watchtower:blacklist',
        'ttl_hours' => 24,
    ]);

    Cache::flush();

    // The deprecation warning is one-shot per process; reset the flag so
    // each test can exercise the warning path independently.
    BlacklistCache::resetDeprecationWarningFlag();

    $this->cache = new BlacklistCache;
});

it('returns false for an IP not in the cache', function () {
    expect($this->cache->isBlocked('9.9.9.9'))->toBeFalse();
});

it('returns true for a permanently blocked IP (empty string value)', function () {
    Cache::store('array')->put('watchtower:blacklist:ip:1.2.3.4', '', 3600);

    expect($this->cache->isBlocked('1.2.3.4'))->toBeTrue();
});

it('returns true for a temporarily blocked IP that has not expired', function () {
    $future = now()->addHour()->toIso8601String();
    Cache::store('array')->put('watchtower:blacklist:ip:1.2.3.4', $future, 3600);

    expect($this->cache->isBlocked('1.2.3.4'))->toBeTrue();
});

it('returns false for a temporarily blocked IP that has expired', function () {
    $past = now()->subHour()->toIso8601String();
    Cache::store('array')->put('watchtower:blacklist:ip:1.2.3.4', $past, 3600);

    expect($this->cache->isBlocked('1.2.3.4'))->toBeFalse();
});

it('does not rebuild on warmOnBoot when the index already exists', function () {
    Cache::store('array')->put('watchtower:blacklist:_index', ['preserved.ip'], 3600);
    Cache::store('array')->put('watchtower:blacklist:ip:preserved.ip', '', 3600);

    // If the early-return works, warmOnBoot is a no-op and the preserved
    // entry stays. If the early-return broke, rebuild() would clear
    // 'preserved.ip' (no DB row backs it).
    $this->cache->warmOnBoot();

    expect(Cache::store('array')->get('watchtower:blacklist:ip:preserved.ip'))->toBe('');
});

it('rebuilds cache on warmOnBoot when the index is missing', function () {
    BlacklistedIp::create([
        'ip'         => '1.2.3.4',
        'source'     => BlockSource::Manual,
        'source_env' => 'testing',
        'expires_at' => null,
    ]);

    expect(Cache::store('array')->has('watchtower:blacklist:_index'))->toBeFalse();

    $this->cache->warmOnBoot();

    expect(Cache::store('array')->get('watchtower:blacklist:ip:1.2.3.4'))->toBe('');
    expect(Cache::store('array')->get('watchtower:blacklist:_index'))->toBe(['1.2.3.4']);
});

it('writes per-IP keys and an index sidecar on rebuild()', function () {
    BlacklistedIp::create([
        'ip'         => '2.2.2.2',
        'source'     => BlockSource::Manual,
        'source_env' => 'testing',
        'expires_at' => now()->addDay(),
    ]);
    BlacklistedIp::create([
        'ip'         => '3.3.3.3',
        'source'     => BlockSource::Manual,
        'source_env' => 'testing',
        'expires_at' => null,
    ]);

    $this->cache->rebuild();

    expect(Cache::store('array')->get('watchtower:blacklist:ip:3.3.3.3'))->toBe('');
    expect(Cache::store('array')->get('watchtower:blacklist:ip:2.2.2.2'))
        ->not->toBeNull()
        ->toBeString();

    $index = Cache::store('array')->get('watchtower:blacklist:_index');
    expect($index)->toBeArray()
        ->toContain('2.2.2.2')
        ->toContain('3.3.3.3');
});

it('forgets stale per-IP entries on rebuild (IP unblocked since last rebuild)', function () {
    // First rebuild: 1.2.3.4 is blocked
    BlacklistedIp::create([
        'ip'         => '1.2.3.4',
        'source'     => BlockSource::Manual,
        'source_env' => 'testing',
        'expires_at' => null,
    ]);
    $this->cache->rebuild();
    expect(Cache::store('array')->has('watchtower:blacklist:ip:1.2.3.4'))->toBeTrue();

    // Unblock 1.2.3.4 in DB, add 5.5.5.5 instead
    BlacklistedIp::where('ip', '1.2.3.4')->delete();
    BlacklistedIp::create([
        'ip'         => '5.5.5.5',
        'source'     => BlockSource::Manual,
        'source_env' => 'testing',
        'expires_at' => null,
    ]);

    $this->cache->rebuild();

    // Stale entry must be gone — without index-driven cleanup it'd sit
    // in the cache for ttl_hours and continue blocking the IP.
    expect(Cache::store('array')->has('watchtower:blacklist:ip:1.2.3.4'))->toBeFalse();
    expect(Cache::store('array')->has('watchtower:blacklist:ip:5.5.5.5'))->toBeTrue();
});

it('clears the index when no IPs are blocked on rebuild', function () {
    Cache::store('array')->put('watchtower:blacklist:_index', ['old.ip'], 3600);
    Cache::store('array')->put('watchtower:blacklist:ip:old.ip', '', 3600);

    // No DB rows — rebuild() should clear both the stale entry and the index
    $this->cache->rebuild();

    expect(Cache::store('array')->has('watchtower:blacklist:_index'))->toBeFalse();
    expect(Cache::store('array')->has('watchtower:blacklist:ip:old.ip'))->toBeFalse();
});

it('keeps existing cache state when DB read fails on rebuild', function () {
    Cache::store('array')->put('watchtower:blacklist:_index', ['preserved.ip'], 3600);
    Cache::store('array')->put('watchtower:blacklist:ip:preserved.ip', '', 3600);

    // Simulate a DB failure by dropping the table
    Schema::drop('blacklisted_ips');

    $this->cache->rebuild();

    // Existing entry should still be there — we'd rather serve stale-but-
    // correct entries than wipe everything when DB is unavailable.
    expect(Cache::store('array')->get('watchtower:blacklist:ip:preserved.ip'))->toBe('');
});

it('emits a deprecation warning when watchtower.cache.connection is set', function () {
    BlacklistCache::resetDeprecationWarningFlag();

    config()->set('watchtower.cache.connection', 'legacy-redis-conn');

    Log::shouldReceive('channel')->andReturnSelf();
    Log::shouldReceive('warning')
        ->once()
        ->withArgs(function (string $message, array $context): bool {
            return str_contains($message, 'watchtower.cache.connection')
                && str_contains($message, 'deprecated')
                && $context['configured_connection'] === 'legacy-redis-conn';
        });

    new BlacklistCache;
});

it('does not emit the deprecation warning when watchtower.cache.connection is unset', function () {
    BlacklistCache::resetDeprecationWarningFlag();

    // Default config has no `connection` key set in beforeEach
    Log::shouldReceive('channel')->andReturnSelf();
    Log::shouldNotReceive('warning');

    new BlacklistCache;
});

it('only emits the deprecation warning once per process', function () {
    BlacklistCache::resetDeprecationWarningFlag();

    config()->set('watchtower.cache.connection', 'some-conn');

    Log::shouldReceive('channel')->andReturnSelf();
    Log::shouldReceive('warning')->once(); // exactly one call across both instantiations

    new BlacklistCache;
    new BlacklistCache; // second instance must NOT re-emit
});

it('warmOnBoot does not throw when the cache backend is unavailable', function () {
    // Point the cache store at a name that doesn't exist — Cache::store('nope')
    // throws. We're verifying that warmOnBoot catches the throw rather than
    // letting the app boot crash.
    config()->set('watchtower.cache.store', 'this-store-does-not-exist');
    $this->cache = new BlacklistCache;

    // Must not throw
    $this->cache->warmOnBoot();

    expect(true)->toBeTrue(); // reaching this line = success
});

it('respects a custom cache key prefix from config', function () {
    config()->set('watchtower.cache.key', 'custom:prefix');
    $this->cache = new BlacklistCache;

    BlacklistedIp::create([
        'ip'         => '7.7.7.7',
        'source'     => BlockSource::Manual,
        'source_env' => 'testing',
        'expires_at' => null,
    ]);

    $this->cache->rebuild();

    expect(Cache::store('array')->get('custom:prefix:ip:7.7.7.7'))->toBe('');
    expect(Cache::store('array')->get('custom:prefix:_index'))->toContain('7.7.7.7');
});
