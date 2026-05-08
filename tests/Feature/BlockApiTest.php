<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Queue;
use Watchtower\Enums\BlockSource;
use Watchtower\Events\IpBlocked;
use Watchtower\Models\BlacklistedIp;
use Watchtower\Services\BlacklistCache;

beforeEach(function () {
    // Use the array cache store — real cache, no Redis-facade mocking.
    // Watchtower's BlacklistCache reads `watchtower.cache.store`, so we
    // pin both that and Laravel's default cache to 'array' for isolation.
    config()->set('cache.default', 'array');
    config()->set('watchtower.cache.store', 'array');
    Cache::flush();

    Event::fake();
    Queue::fake();

    // Bypass LogScope's Authorize middleware in tests
    $this->withoutMiddleware(\LogScope\Http\Middleware\Authorize::class);
});

it('blocks an IP via the API and updates the database', function () {
    $response = $this->postJson('/logscope/watchtower/api/block', [
        'ip'     => '10.0.0.1',
        'reason' => 'suspicious traffic',
    ]);

    $response->assertStatus(200)
        ->assertJsonPath('data.ip', '10.0.0.1')
        ->assertJsonPath('data.reason', 'suspicious traffic');

    $this->assertDatabaseHas('blacklisted_ips', [
        'ip'     => '10.0.0.1',
        'source' => 'manual',
    ]);

    Event::assertDispatched(IpBlocked::class);
});

it('returns 422 when trying to block a whitelisted IP', function () {
    config()->set('watchtower.never_block', ['127.0.0.1']);

    $response = $this->postJson('/logscope/watchtower/api/block', ['ip' => '127.0.0.1']);

    $response->assertStatus(422)
        ->assertJsonStructure(['error']);
});

it('unblocks an IP via the API', function () {
    BlacklistedIp::create([
        'ip'         => '10.0.0.2',
        'source'     => BlockSource::Manual,
        'source_env' => 'testing',
    ]);

    $response = $this->deleteJson('/logscope/watchtower/api/block/10.0.0.2');

    $response->assertStatus(200)
        ->assertJsonPath('deleted', true);

    $this->assertDatabaseMissing('blacklisted_ips', ['ip' => '10.0.0.2']);
});

it('returns the correct status for a blocked IP', function () {
    BlacklistedIp::create([
        'ip'         => '10.0.0.3',
        'source'     => BlockSource::Manual,
        'source_env' => 'testing',
        'expires_at' => null,
    ]);

    // status() checks the cache as truth — write a permanent-block entry
    // (empty string value) for the IP so isBlocked() returns true.
    Cache::store('array')->put('watchtower:blacklist:ip:10.0.0.3', '', 3600);

    $response = $this->getJson('/logscope/watchtower/api/status/10.0.0.3');

    $response->assertStatus(200)
        ->assertJsonPath('blocked', true);
});

it('returns the correct status for an unblocked IP', function () {
    $response = $this->getJson('/logscope/watchtower/api/status/9.9.9.9');

    $response->assertStatus(200)
        ->assertJsonPath('blocked', false);
});

it('returns the full list of active blocks', function () {
    BlacklistedIp::create(['ip' => '1.1.1.1', 'source' => BlockSource::Manual, 'source_env' => 'testing']);
    BlacklistedIp::create(['ip' => '2.2.2.2', 'source' => BlockSource::Auto, 'source_env' => 'testing']);

    $response = $this->getJson('/logscope/watchtower/api/blocks');

    $response->assertStatus(200)
        ->assertJsonCount(2, 'data');
});

it('does not return expired blocks in the list', function () {
    BlacklistedIp::create(['ip' => '1.1.1.1', 'source' => BlockSource::Manual, 'source_env' => 'testing', 'expires_at' => now()->subHour()]);
    BlacklistedIp::create(['ip' => '2.2.2.2', 'source' => BlockSource::Manual, 'source_env' => 'testing', 'expires_at' => now()->addHour()]);

    $response = $this->getJson('/logscope/watchtower/api/blocks');

    $response->assertStatus(200)
        ->assertJsonCount(1, 'data');
});
