<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Queue;
use Watchtower\Enums\BlockSource;
use Watchtower\Events\IpBlocked;
use Watchtower\Jobs\PushBlockToMaster;
use Watchtower\Models\BlacklistedIp;
use Watchtower\Services\BlacklistCache;
use Watchtower\Services\BlacklistService;

beforeEach(function () {
    $this->cache = Mockery::mock(BlacklistCache::class);
    $this->cache->shouldReceive('rebuild')->andReturn(null)->byDefault();
    $this->cache->shouldReceive('warmOnBoot')->andReturn(null)->byDefault();

    $this->service = new BlacklistService($this->cache);
});

it('blocks an IP and creates a DB record', function () {
    Event::fake();
    Queue::fake();

    $record = $this->service->block('1.2.3.4', ['reason' => 'test block']);

    expect($record)->toBeInstanceOf(BlacklistedIp::class)
        ->and($record->ip)->toBe('1.2.3.4')
        ->and($record->reason)->toBe('test block')
        ->and($record->source)->toBe(BlockSource::Manual);

    $this->assertDatabaseHas('blacklisted_ips', ['ip' => '1.2.3.4']);
});

it('fires the IpBlocked event on block', function () {
    Event::fake();
    Queue::fake();

    $this->service->block('1.2.3.4');

    Event::assertDispatched(IpBlocked::class, fn ($e) => $e->record->ip === '1.2.3.4');
});

it('dispatches PushBlockToMaster when master URL is configured', function () {
    Event::fake();
    Queue::fake();
    config()->set('watchtower.sync.master_url', 'https://master.example.com');

    $this->service->block('1.2.3.4');

    Queue::assertPushed(PushBlockToMaster::class);
});

it('does not dispatch PushBlockToMaster when master URL is not configured', function () {
    Event::fake();
    Queue::fake();
    config()->set('watchtower.sync.master_url', null);

    $this->service->block('1.2.3.4');

    Queue::assertNotPushed(PushBlockToMaster::class);
});

it('throws when blocking a never-block whitelisted IP', function () {
    config()->set('watchtower.never_block', ['1.2.3.4']);

    expect(fn () => $this->service->block('1.2.3.4'))
        ->toThrow(RuntimeException::class, 'never-block whitelist');
});

it('unblocks an IP and removes the DB record', function () {
    BlacklistedIp::create([
        'ip'         => '1.2.3.4',
        'source'     => BlockSource::Manual,
        'source_env' => 'testing',
    ]);

    $result = $this->service->unblock('1.2.3.4');

    expect($result)->toBeTrue();
    $this->assertDatabaseMissing('blacklisted_ips', ['ip' => '1.2.3.4']);
});

it('returns false when unblocking a non-existent IP', function () {
    $result = $this->service->unblock('9.9.9.9');

    expect($result)->toBeFalse();
});

it('normalizes IPv4-mapped IPv6 addresses', function () {
    $normalized = $this->service->normalizeIp('::ffff:1.2.3.4');

    expect($normalized)->toBe('1.2.3.4');
});

it('normalizes full IPv6 addresses', function () {
    $normalized = $this->service->normalizeIp('2001:0db8:0000:0000:0000:0000:0000:0001');

    expect($normalized)->toBe('2001:db8::1');
});

it('upserts rather than duplicating when blocking an already-blocked IP', function () {
    Event::fake();
    Queue::fake();

    $this->service->block('5.5.5.5', ['reason' => 'first']);
    $this->service->block('5.5.5.5', ['reason' => 'second']);

    $this->assertDatabaseCount('blacklisted_ips', 1);
    expect(BlacklistedIp::where('ip', '5.5.5.5')->first()->reason)->toBe('second');
});
