<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Event;
use Watchtower\Enums\BlockSource;
use Watchtower\Events\IpUnblocked;
use Watchtower\Models\BlacklistedIp;
use Watchtower\Services\BlacklistCache;
use Watchtower\Support\BlockScope;

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

it('fires IpUnblocked for an expired global block, so a block target learns it lapsed', function () {
    Event::fake();

    BlacklistedIp::create([
        'ip'         => '1.2.3.4',
        'scope'      => BlockScope::GLOBAL,
        'source'     => BlockSource::Auto,
        'source_env' => 'testing',
        'expires_at' => now()->subHour(),
    ]);

    $this->artisan('watchtower:cleanup')->assertSuccessful();

    Event::assertDispatched(IpUnblocked::class, fn ($e) => $e->ip === '1.2.3.4');
});

it('does not fire IpUnblocked for an expired SCOPED block', function () {
    Event::fake();
    config()->set('watchtower.scopes', ['auth']);

    BlacklistedIp::create([
        'ip'         => '1.2.3.4',
        'scope'      => 'auth',
        'source'     => BlockSource::Auto,
        'source_env' => 'testing',
        'expires_at' => now()->subHour(),
    ]);

    $this->artisan('watchtower:cleanup')->assertSuccessful();

    Event::assertNotDispatched(IpUnblocked::class);
});

it('fires no events when nothing expired', function () {
    Event::fake();

    BlacklistedIp::create([
        'ip'         => '2.2.2.2',
        'scope'      => BlockScope::GLOBAL,
        'source'     => BlockSource::Auto,
        'source_env' => 'testing',
        'expires_at' => now()->addHour(),
    ]);

    $this->artisan('watchtower:cleanup')->assertSuccessful();

    Event::assertNotDispatched(IpUnblocked::class);
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

it('fails instead of reporting success when the cache rebuild fails', function () {
    BlacklistedIp::create([
        'ip'         => '6.6.6.6',
        'source'     => BlockSource::Auto,
        'source_env' => 'testing',
        'expires_at' => now()->subHour(),
    ]);

    // The row is deleted either way — a failed rebuild leaves the cache saying
    // 6.6.6.6 is still blocked until the entry hits its TTL, so someone whose
    // block just expired stays locked out. A green cron run would hide that.
    $cache = Mockery::mock(BlacklistCache::class)->shouldIgnoreMissing();
    $cache->shouldReceive('rebuild')->once()->andReturnFalse();
    $this->app->instance(BlacklistCache::class, $cache);

    $this->artisan('watchtower:cleanup')
        ->assertFailed()
        ->expectsOutputToContain('cache rebuild failed');

    $this->assertDatabaseMissing('blacklisted_ips', ['ip' => '6.6.6.6']);
});

it('flushes a pending hit count into hits and last_hit_at', function () {
    $block = BlacklistedIp::create([
        'ip'         => '7.7.7.7',
        'source'     => BlockSource::Manual,
        'source_env' => 'testing',
        'expires_at' => null,
    ]);

    $cache = app(BlacklistCache::class);
    $cache->rebuild();
    $cache->recordHit('7.7.7.7');
    $cache->recordHit('7.7.7.7');
    $cache->recordHit('7.7.7.7');

    $this->artisan('watchtower:cleanup')
        ->assertSuccessful()
        ->expectsOutputToContain('Flushed hit counts for 1 block(s).');

    $block->refresh();

    expect($block->hits)->toBe(3)
        ->and($block->last_hit_at)->not->toBeNull();

    // Cleared, not merely read: the next flush must not double-count it.
    expect($cache->pullHits('7.7.7.7'))->toBe(0);
});

it('attributes hits to the right (ip, scope) pair when both exist for the same address', function () {
    config()->set('watchtower.scopes', ['auth']);

    $global = BlacklistedIp::create([
        'ip'         => '8.8.8.8',
        'scope'      => BlockScope::GLOBAL,
        'source'     => BlockSource::Manual,
        'source_env' => 'testing',
    ]);

    $scoped = BlacklistedIp::create([
        'ip'         => '8.8.8.8',
        'scope'      => 'auth',
        'source'     => BlockSource::Manual,
        'source_env' => 'testing',
    ]);

    $cache = app(BlacklistCache::class);
    $cache->rebuild();
    $cache->recordHit('8.8.8.8');
    $cache->recordHit('8.8.8.8', 'auth');
    $cache->recordHit('8.8.8.8', 'auth');

    $this->artisan('watchtower:cleanup')->assertSuccessful();

    expect($global->refresh()->hits)->toBe(1)
        ->and($scoped->refresh()->hits)->toBe(2);
});

it('does not report a flush when nothing was pending', function () {
    BlacklistedIp::create([
        'ip'         => '9.9.9.9',
        'source'     => BlockSource::Manual,
        'source_env' => 'testing',
    ]);

    $this->artisan('watchtower:cleanup')
        ->assertSuccessful()
        ->doesntExpectOutputToContain('Flushed hit counts');
});

it('does not let a hit-flush failure stop expired blocks from being cleaned up', function () {
    BlacklistedIp::create([
        'ip'         => '10.10.10.10',
        'source'     => BlockSource::Auto,
        'source_env' => 'testing',
        'expires_at' => now()->subHour(),
    ]);

    $cache = Mockery::mock(BlacklistCache::class)->shouldIgnoreMissing();
    $cache->shouldReceive('pullHitsFor')->andThrow(new RuntimeException('cache down'));
    $cache->shouldReceive('rebuild')->once()->andReturnTrue();
    $this->app->instance(BlacklistCache::class, $cache);

    $this->artisan('watchtower:cleanup')
        ->assertSuccessful()
        ->expectsOutputToContain('Could not flush hit counts')
        ->expectsOutputToContain('Removed 1 expired block');

    $this->assertDatabaseMissing('blacklisted_ips', ['ip' => '10.10.10.10']);
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
