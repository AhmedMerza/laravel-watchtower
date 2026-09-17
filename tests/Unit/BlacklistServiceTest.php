<?php

declare(strict_types=1);

use Carbon\Carbon;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Queue;
use Watchtower\Enums\BlockSource;
use Watchtower\Events\IpBlocked;
use Watchtower\Exceptions\NeverBlockException;
use Watchtower\Jobs\PushBlockToMaster;
use Watchtower\Models\BlacklistedIp;
use Watchtower\Services\BlacklistCache;
use Watchtower\Services\BlacklistService;

beforeEach(function () {
    $this->cache = Mockery::mock(BlacklistCache::class);
    $this->cache->shouldReceive('rebuild')->andReturn(true)->byDefault();
    $this->cache->shouldReceive('forget')->byDefault();
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
        ->toThrow(NeverBlockException::class, 'never-block whitelist');
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

describe('when the cache rebuild fails', function () {
    beforeEach(function () {
        config()->set('watchtower.cache', ['store' => 'array', 'key' => 'watchtower:blacklist', 'ttl_hours' => 24]);
        Cache::store('array')->flush();

        // rebuild() reports a failed DB read by returning false and leaving
        // the cache alone. Both services share the array store.
        $this->failing = new BlacklistService(new class extends BlacklistCache
        {
            public function rebuild(): bool
            {
                return false;
            }
        });
        $this->working = new BlacklistService(new BlacklistCache);
    });

    it('still enforces the block', function (?Carbon $expiresAt) {
        Event::fake();
        Queue::fake();

        $this->failing->block('1.2.3.4', ['expires_at' => $expiresAt]);

        expect($this->working->isBlocked('1.2.3.4'))->toBeTrue();
    })->with([
        'permanent' => null,
        'temporary' => fn () => now()->addHour(),
    ]);

    it('writes a temporary block that lapses on its own expiry', function () {
        Event::fake();
        Queue::fake();

        $this->failing->block('1.2.3.4', ['expires_at' => now()->addHour()]);
        $this->travel(61)->minutes();

        expect($this->working->isBlocked('1.2.3.4'))->toBeFalse();
    });

    it('leaves the index to expire with the entries it was written alongside', function () {
        Event::fake();
        Queue::fake();
        Cache::store('array')->put('watchtower:blacklist:_index', ['5.6.7.8'], 3600);

        $this->failing->block('1.2.3.4');

        // Rewriting the index here would restart its TTL, and warmOnBoot()
        // would go on reading "warm" after the entries it lists had expired.
        expect(Cache::store('array')->get('watchtower:blacklist:_index'))->toBe(['5.6.7.8']);
        $this->travel(61)->minutes();
        expect(Cache::store('array')->has('watchtower:blacklist:_index'))->toBeFalse();
    });

    it('still lifts the block', function () {
        Event::fake();
        Queue::fake();
        $this->working->block('1.2.3.4');

        $this->failing->unblock('1.2.3.4');

        expect($this->working->isBlocked('1.2.3.4'))->toBeFalse();
    });

    it('lifts a block written by the fallback once rebuilds work again', function () {
        Event::fake();
        Queue::fake();
        $this->failing->block('1.2.3.4');

        // The fallback entry isn't in the index, so this rebuild alone
        // wouldn't forget it.
        $this->working->unblock('1.2.3.4');

        expect($this->working->isBlocked('1.2.3.4'))->toBeFalse();
    });
});
