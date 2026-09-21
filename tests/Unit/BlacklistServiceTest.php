<?php

declare(strict_types=1);

use Carbon\Carbon;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
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
    $this->cache->shouldReceive('write')->byDefault();
    $this->cache->shouldReceive('rebuild')->andReturn(true)->byDefault();
    $this->cache->shouldReceive('forget')->byDefault();

    $this->service = new BlacklistService($this->cache);
});

it('blocks an IP and creates a DB record', function () {
    Event::fake();
    Queue::fake();

    // Acceptance criterion: creating a block writes one cache key rather
    // than rebuilding the whole blocklist. Asserted at the call site, not
    // just on BlacklistCache::write() in isolation — otherwise a revert to
    // the old rebuild()-or-put() pattern would leave every test green.
    $this->cache->shouldReceive('write')->once();
    $this->cache->shouldReceive('rebuild')->never();

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

it('pushes to master on the queue sync.queue names', function () {
    Event::fake();
    Queue::fake();
    config()->set('watchtower.sync.master_url', 'https://master.example.com');
    config()->set('watchtower.sync.queue', 'sync');

    $this->service->block('1.2.3.4');

    Queue::assertPushedOn('sync', PushBlockToMaster::class);
});

// The push job read watchtower.notifications.queue until #50 moved it to its
// own key. Without this fallback an app that had set the notification queue —
// and runs a worker only for it — would upgrade into a push job queued where
// nothing consumes it, which is the silent failure #50 is about, moved.
it('falls back to the notification queue when no sync queue is named', function () {
    putenv('WATCHTOWER_NOTIFICATION_QUEUE=notifications');

    try {
        $config = require __DIR__.'/../../config/watchtower.php';

        expect($config['sync']['queue'])->toBe('notifications');
    } finally {
        putenv('WATCHTOWER_NOTIFICATION_QUEUE');
    }
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

        // Rewriting the index here would restart its TTL, so it would
        // outlive the entries it lists.
        expect(Cache::store('array')->get('watchtower:blacklist:_index'))->toBe(['5.6.7.8']);
        $this->travel(61)->minutes();
        expect(Cache::store('array')->has('watchtower:blacklist:_index'))->toBeFalse();
    });

    it('still enforces a blocked RANGE, the case that actually reaches rebuild()', function () {
        Event::fake();
        Queue::fake();

        // Every other case in this block targets a single address, and
        // BlacklistCache::write() answers those with one put() without ever
        // calling rebuild() — so the failing rebuild() above is never
        // invoked and those cases pass on the fast path rather than on the
        // fallback they are named for. A range is the only input that still
        // goes through rebuild(), so this is what keeps the fallback
        // covered from the BlacklistService side.
        $this->failing->block('198.18.0.0/16');

        expect($this->working->isBlocked('198.18.4.4'))->toBeTrue();
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

    it('still lifts a scoped block', function () {
        Event::fake();
        Queue::fake();
        config()->set('watchtower.scopes', ['auth']);

        $this->working->block('1.2.3.4', ['scope' => 'auth']);

        $this->failing->unblock('1.2.3.4');

        // unblock() forgets each scope's key BEFORE rebuilding, which is the
        // only thing that lifts this when the rebuild can't read the DB. With
        // a working rebuild the namespaces are rewritten from the table and
        // this passes either way — so a rebuild that works would make the
        // test vacuous, the way #23's fallback test went quietly dead.
        expect($this->working->isBlocked('1.2.3.4', 'auth'))->toBeFalse();
    });
});

describe('ranges and IPv6 prefixes', function () {
    beforeEach(function () {
        Event::fake();
        Queue::fake();
        config()->set('watchtower.cache', ['store' => 'array', 'key' => 'watchtower:blacklist', 'ttl_hours' => 24]);
        config()->set('watchtower.never_block', []);
        Cache::store('array')->flush();

        $this->service = new BlacklistService(new BlacklistCache);
    });

    it('stores a single IPv6 address as its /64 and blocks the whole /64', function () {
        $record = $this->service->block('2001:db8:1:2::1');

        expect($record->ip)->toBe('2001:db8:1:2::/64')
            ->and($this->service->isBlocked('2001:db8:1:2:aaaa::5'))->toBeTrue()
            ->and($this->service->isBlocked('2001:db8:1:3::1'))->toBeFalse();
    });

    it('blocks exactly one IPv6 address given as /128', function () {
        $record = $this->service->block('2001:db8::1/128');

        expect($record->ip)->toBe('2001:db8::1')
            ->and($this->service->isBlocked('2001:db8::1'))->toBeTrue()
            ->and($this->service->isBlocked('2001:db8::2'))->toBeFalse();
    });

    it('stores a range as its network address', function () {
        expect($this->service->block('203.0.113.77/24')->ip)->toBe('203.0.113.0/24')
            ->and($this->service->isBlocked('203.0.113.1'))->toBeTrue();
    });

    it('refuses a target the never-block list covers', function (string $target) {
        config()->set('watchtower.never_block', ['10.0.0.0/8']);

        expect(fn () => $this->service->block($target))
            ->toThrow(NeverBlockException::class, 'never-block whitelist');
        $this->assertDatabaseCount('blacklisted_ips', 0);
    })->with(['10.1.2.3', '10.1.0.0/16', '10.0.0.0/8']);

    it('blocks a range that only overlaps a never-block entry', function () {
        config()->set('watchtower.never_block', ['10.0.0.1']);

        expect($this->service->block('10.0.0.0/24')->ip)->toBe('10.0.0.0/24');
    });

    it('refuses a never-block IPv6 address but still blocks its neighbours\' /64', function () {
        config()->set('watchtower.never_block', ['2001:db8::1']);

        expect(fn () => $this->service->block('2001:db8::1'))->toThrow(NeverBlockException::class);
        expect($this->service->block('2001:db8::2')->ip)->toBe('2001:db8::/64');
    });

    it('unblocks a /64 from any address inside it', function () {
        $this->service->block('2001:db8::1');

        expect($this->service->unblock('2001:db8::abcd'))->toBeTrue()
            ->and($this->service->isBlocked('2001:db8::1'))->toBeFalse();
    });

    it('unblocks a bare IPv6 row left from before prefixes', function () {
        BlacklistedIp::create(['ip' => '2001:db8::5', 'source' => BlockSource::Manual]);

        expect($this->service->unblock('2001:db8::5'))->toBeTrue()
            ->and($this->service->isBlocked('2001:db8::5'))->toBeFalse();
    });

    it('unblocks a range by its CIDR', function () {
        $this->service->block('203.0.113.0/24');

        expect($this->service->unblock('203.0.113.9/24'))->toBeTrue()
            ->and($this->service->isBlocked('203.0.113.9'))->toBeFalse();
    });

    it('leaves a range in place when one IP inside it is unblocked', function () {
        $this->service->block('203.0.113.0/24');

        expect($this->service->unblock('203.0.113.9'))->toBeFalse()
            ->and($this->service->isBlocked('203.0.113.9'))->toBeTrue();
    });

    it('reports a never-block address as unblocked, as the middleware treats it', function (string $neverBlock, string $blocked, string $protected) {
        config()->set('watchtower.never_block', [$neverBlock]);
        $this->service->block($blocked);

        // Status said "blocked" here while the middleware let the address
        // through — and LogScope's Unblock button then lifted the whole block.
        expect($this->service->isBlocked($protected))->toBeFalse()
            ->and($this->service->isBlocked($blocked))->toBeTrue();
    })->with([
        'IPv6 address inside a blocked /64' => ['2001:db8::1', '2001:db8::2', '2001:db8::1'],
        'IPv4 address inside a blocked /24' => ['10.0.0.1', '10.0.0.0/24', '10.0.0.1'],
    ]);

    it('reports a range that a wider blocked range covers', function () {
        $this->service->block('203.0.113.0/24');

        expect($this->service->isBlocked('203.0.113.0/25'))->toBeTrue()
            ->and($this->service->find('203.0.113.0/25')?->ip)->toBe('203.0.113.0/24')
            ->and($this->service->isBlocked('198.51.100.0/25'))->toBeFalse();
    });

    it('prefers the range now blocking an IP over its own lapsed row', function () {
        BlacklistedIp::create(['ip' => '203.0.113.9', 'source' => BlockSource::Manual, 'expires_at' => now()->subMinute()]);
        $this->service->block('203.0.113.0/24');

        expect($this->service->find('203.0.113.9')?->ip)->toBe('203.0.113.0/24');
    });

    it('reports an expired range as unblocked while still naming its row', function () {
        BlacklistedIp::create(['ip' => '203.0.113.0/24', 'source' => BlockSource::Manual, 'expires_at' => now()->subMinute()]);

        expect($this->service->isBlocked('203.0.113.0/24'))->toBeFalse()
            ->and($this->service->find('203.0.113.0/24')?->ip)->toBe('203.0.113.0/24');
    });

    it('skips a malformed range row when looking for what blocks an IP', function () {
        BlacklistedIp::create(['ip' => 'not-an-ip/24', 'source' => BlockSource::Manual]);
        $this->service->block('203.0.113.0/24');

        expect($this->service->find('203.0.113.9')?->ip)->toBe('203.0.113.0/24')
            ->and($this->service->find('198.51.100.9'))->toBeNull();
    });

    it('answers a query that is not an IP at all', function () {
        $this->service->block('203.0.113.0/24');

        // Without the null guard, the covering-range search hands null to a
        // string parameter under strict_types — a 500 on /api/status/{junk}.
        expect($this->service->find('not-an-ip'))->toBeNull()
            ->and($this->service->isBlocked('not-an-ip'))->toBeFalse();
    });

    it('prefers the row for the exact address when its /64 is blocked too', function () {
        $this->service->block('2001:db8::1/128', ['reason' => 'this address']);
        $this->service->block('2001:db8::2', ['reason' => 'the whole /64']);

        // Both rows are live and the query has no order of its own.
        expect(BlacklistedIp::count())->toBe(2)
            ->and($this->service->find('2001:db8::1')?->reason)->toBe('this address');
    });

    it('looks the record up once when reporting status for a range', function () {
        $this->service->block('203.0.113.0/24');

        DB::enableQueryLog();
        $status = $this->service->status('203.0.113.0/25');
        $queries = DB::getQueryLog();
        DB::disableQueryLog();

        expect($status['blocked'])->toBeTrue()
            ->and($status['record']?->ip)->toBe('203.0.113.0/24')
            // find() runs the own-row lookup plus the covering-range scan.
            // Asking isBlocked() separately would double both.
            ->and($queries)->toHaveCount(2);
    });

    it('finds the range blocking an IP that has no row of its own', function () {
        $this->service->block('203.0.113.0/24');
        $this->service->block('198.51.100.0/24', ['expires_at' => now()->subMinute()]);

        expect($this->service->find('203.0.113.9')?->ip)->toBe('203.0.113.0/24')
            ->and($this->service->find('198.51.100.9'))->toBeNull()
            ->and($this->service->find('192.0.2.1'))->toBeNull();
    });

    it('prefers an IP\'s own row over a range that covers it', function () {
        $this->service->block('203.0.113.0/24');
        $this->service->block('203.0.113.9', ['reason' => 'its own']);

        expect($this->service->find('203.0.113.9')?->reason)->toBe('its own');
    });
});

it('keeps a local manual block rather than letting a synced record downgrade it', function () {
    Event::fake();
    Queue::fake();

    BlacklistedIp::create([
        'ip'         => '1.2.3.4',
        'reason'     => 'blocked here by hand',
        'source'     => BlockSource::Manual,
        'source_env' => 'production',
    ]);

    $result = $this->service->applySync('1.2.3.4', ['reason' => 'from a satellite', 'source_env' => 'staging']);

    // The rule lived in SyncController and again in SyncCommand before #38.
    // Both now call this, so there is one place for it to be wrong.
    expect($result['applied'])->toBeFalse()
        ->and($result['record']->source)->toBe(BlockSource::Manual)
        ->and($result['record']->reason)->toBe('blocked here by hand');

    Event::assertNotDispatched(IpBlocked::class);
    $this->assertDatabaseCount('blacklisted_ips', 1);
});

it('updates a row that is itself a synced block', function () {
    Event::fake();
    Queue::fake();

    BlacklistedIp::create([
        'ip'         => '1.2.3.4',
        'reason'     => 'an older sync',
        'source'     => BlockSource::Sync,
        'source_env' => 'production',
    ]);

    $result = $this->service->applySync('1.2.3.4', ['reason' => 'a newer sync', 'source_env' => 'production']);

    expect($result['applied'])->toBeTrue()
        ->and($result['record']->reason)->toBe('a newer sync');

    $this->assertDatabaseCount('blacklisted_ips', 1);
});

it('refuses to apply a synced block for a never-block address', function () {
    Event::fake();
    Queue::fake();
    config()->set('watchtower.never_block', ['10.0.0.0/8']);

    expect(fn () => $this->service->applySync('10.0.0.1', ['source_env' => 'production']))
        ->toThrow(NeverBlockException::class);

    // The row is what matters, not just the refusal: the pull path used to
    // write one, and config/watchtower.php promises never_block covers a
    // block arriving "by any means — UI, auto-block, or sync".
    $this->assertDatabaseCount('blacklisted_ips', 0);
});

it('refuses a never-block address even when it already holds a row', function () {
    Event::fake();
    Queue::fake();

    // Whitelisted after the block was made, which is the order that actually
    // happens. never_block is checked ahead of the downgrade guard so the
    // answer doesn't depend on what is in the table.
    BlacklistedIp::create(['ip' => '10.0.0.1', 'source' => BlockSource::Sync, 'source_env' => 'production']);
    config()->set('watchtower.never_block', ['10.0.0.1']);

    expect(fn () => $this->service->applySync('10.0.0.1', ['source_env' => 'production']))
        ->toThrow(NeverBlockException::class);

    $this->assertDatabaseHas('blacklisted_ips', ['ip' => '10.0.0.1', 'reason' => null]);
});

it('does not push a synced block onward to the master', function () {
    Event::fake();
    Queue::fake();
    config()->set('watchtower.sync.master_url', 'https://master.example.com');

    $this->service->applySync('1.2.3.4', ['source_env' => 'staging']);

    // A block replicated from elsewhere is not this node's to report.
    // PushBlockToMaster drops a Sync record anyway, so dispatching one only
    // ever queued a job that returned immediately.
    Queue::assertNotPushed(PushBlockToMaster::class);
});

it('defers the cache write and stays silent when the caller asks', function () {
    Event::fake();
    Queue::fake();

    // What watchtower:sync passes: it rebuilds once for the whole run, and a
    // pulled block was already announced by the environment that received it.
    $this->cache->shouldReceive('write')->never();
    $this->cache->shouldReceive('put')->never();

    $result = $this->service->applySync('1.2.3.4', ['source_env' => 'production'], deferCache: true, announce: false);

    expect($result['applied'])->toBeTrue();
    Event::assertNotDispatched(IpBlocked::class);
});

it('writes the cache entry and announces by default', function () {
    Event::fake();
    Queue::fake();

    // What SyncController::receive() passes — a single block arriving as news.
    $this->cache->shouldReceive('write')->once();

    $this->service->applySync('1.2.3.4', ['source_env' => 'staging']);

    Event::assertDispatched(IpBlocked::class, fn ($e) => $e->record->ip === '1.2.3.4');
});
