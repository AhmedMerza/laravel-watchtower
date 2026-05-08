<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Cache;
use Watchtower\Enums\BlockSource;
use Watchtower\Models\BlacklistedIp;

beforeEach(function () {
    config()->set('cache.default', 'array');
    config()->set('watchtower.cache.store', 'array');
    Cache::flush();
});

it('deletes expired temporary blocks', function () {
    BlacklistedIp::create([
        'ip'         => '1.2.3.4',
        'source'     => BlockSource::Auto,
        'source_env' => 'testing',
        'expires_at' => now()->subHour(),
    ]);

    $this->artisan('watchtower:cleanup')
        ->assertSuccessful()
        ->expectsOutputToContain('Removed 1 expired block');

    $this->assertDatabaseMissing('blacklisted_ips', ['ip' => '1.2.3.4']);
});

it('does not delete blocks that have not expired yet', function () {
    BlacklistedIp::create([
        'ip'         => '2.2.2.2',
        'source'     => BlockSource::Auto,
        'source_env' => 'testing',
        'expires_at' => now()->addHour(),
    ]);

    $this->artisan('watchtower:cleanup')->assertSuccessful();

    $this->assertDatabaseHas('blacklisted_ips', ['ip' => '2.2.2.2']);
});

it('never deletes permanent blocks (expires_at is null)', function () {
    BlacklistedIp::create([
        'ip'         => '3.3.3.3',
        'source'     => BlockSource::Manual,
        'source_env' => 'testing',
        'expires_at' => null,
    ]);

    $this->artisan('watchtower:cleanup')
        ->assertSuccessful()
        ->expectsOutputToContain('Nothing to clean up');

    $this->assertDatabaseHas('blacklisted_ips', ['ip' => '3.3.3.3']);
});

it('only rebuilds the cache when records were deleted', function () {
    // Pre-populate the cache index with a sentinel — rebuild() would clear
    // and rewrite it. If cleanup correctly skips rebuild when no records
    // are deleted, the sentinel survives.
    Cache::store('array')->put('watchtower:blacklist:_index', ['preserved.sentinel.ip'], 3600);
    Cache::store('array')->put('watchtower:blacklist:ip:preserved.sentinel.ip', '', 3600);

    BlacklistedIp::create([
        'ip'         => '4.4.4.4',
        'source'     => BlockSource::Manual,
        'source_env' => 'testing',
        'expires_at' => null,
    ]);

    $this->artisan('watchtower:cleanup')->assertSuccessful();

    // No expired blocks → rebuild() shouldn't have been called → sentinel remains.
    expect(Cache::store('array')->get('watchtower:blacklist:_index'))->toBe(['preserved.sentinel.ip']);
});

it('reports nothing to clean up when the table is empty', function () {
    $this->artisan('watchtower:cleanup')
        ->assertSuccessful()
        ->expectsOutputToContain('Nothing to clean up');
});

it('can still be run manually even when WATCHTOWER_CLEANUP_ENABLED is false', function () {
    config()->set('watchtower.cleanup.enabled', false);

    BlacklistedIp::create([
        'ip'         => '5.5.5.5',
        'source'     => BlockSource::Auto,
        'source_env' => 'testing',
        'expires_at' => now()->subHour(),
    ]);

    // The config flag only stops the scheduler — the command itself still works
    $this->artisan('watchtower:cleanup')
        ->assertSuccessful()
        ->expectsOutputToContain('Removed 1 expired block');

    $this->assertDatabaseMissing('blacklisted_ips', ['ip' => '5.5.5.5']);
});
