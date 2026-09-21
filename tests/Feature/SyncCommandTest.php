<?php

declare(strict_types=1);

use Illuminate\Database\QueryException;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Http;
use Watchtower\Enums\BlockSource;
use Watchtower\Events\IpBlocked;
use Watchtower\Models\BlacklistedIp;
use Watchtower\Services\BlacklistCache;

beforeEach(function () {
    config()->set('cache.default', 'array');
    config()->set('watchtower.cache.store', 'array');
    Cache::flush();

    config()->set('watchtower.sync.master_url', 'https://master.example.com');
    config()->set('watchtower.sync.secret', 'test-secret');
});

it('syncs IPs from master and upserts them locally', function () {
    Http::fake([
        'master.example.com/watchtower/sync/blocks' => Http::response([
            'data' => [
                ['ip' => '1.2.3.4', 'reason' => 'synced', 'source_env' => 'production', 'expires_at' => null, 'blocked_by' => null, 'log_entry_id' => null],
                ['ip' => '5.6.7.8', 'reason' => null, 'source_env' => 'production', 'expires_at' => null, 'blocked_by' => null, 'log_entry_id' => null],
            ],
        ], 200),
    ]);

    $this->artisan('watchtower:sync')
        ->assertSuccessful()
        ->expectsOutputToContain('Synced 2 IPs');

    $this->assertDatabaseHas('blacklisted_ips', ['ip' => '1.2.3.4', 'source' => 'sync']);
    $this->assertDatabaseHas('blacklisted_ips', ['ip' => '5.6.7.8', 'source' => 'sync']);
});

it('fails gracefully when master returns an error', function () {
    Http::fake([
        'master.example.com/watchtower/sync/blocks' => Http::response([], 500),
    ]);

    $this->artisan('watchtower:sync')
        ->assertFailed()
        ->expectsOutputToContain('HTTP 500');
});

it('fails gracefully when master URL is not configured', function () {
    config()->set('watchtower.sync.master_url', null);

    $this->artisan('watchtower:sync')
        ->assertFailed()
        ->expectsOutputToContain('WATCHTOWER_MASTER_URL');
});

it('enforces the synced IPs but still fails when the cache rebuild fails', function () {
    Http::fake([
        'master.example.com/watchtower/sync/blocks' => Http::response([
            'data' => [
                ['ip' => '1.2.3.4', 'reason' => 'synced', 'source_env' => 'production', 'expires_at' => null, 'blocked_by' => null, 'log_entry_id' => null],
            ],
        ], 200),
    ]);

    // rebuild() logs its own DB failure and returns false, keeping the stale
    // cache. The middleware reads only the cache, so the synced IP must be
    // written there anyway, and the exit code must still tell cron.
    $this->app->instance(BlacklistCache::class, new class extends BlacklistCache
    {
        public function rebuild(): bool
        {
            return false;
        }
    });

    $this->artisan('watchtower:sync')
        ->assertFailed()
        ->expectsOutputToContain('cache rebuild failed');

    $this->assertDatabaseHas('blacklisted_ips', ['ip' => '1.2.3.4']);
    expect((new BlacklistCache)->isBlocked('1.2.3.4'))->toBeTrue();
});

it('does not duplicate records on repeated syncs', function () {
    Http::fake([
        'master.example.com/watchtower/sync/blocks' => Http::response([
            'data' => [
                ['ip' => '1.2.3.4', 'reason' => 'initial', 'source_env' => 'production', 'expires_at' => null, 'blocked_by' => null, 'log_entry_id' => null],
            ],
        ], 200),
    ]);

    $this->artisan('watchtower:sync');
    $this->artisan('watchtower:sync');

    $this->assertDatabaseCount('blacklisted_ips', 1);
});

it('does not overwrite a local scoped block with a synced global one', function () {
    config()->set('watchtower.scopes', ['auth']);

    BlacklistedIp::create([
        'ip'         => '1.2.3.4',
        'scope'      => 'auth',
        'source'     => BlockSource::Manual,
        'source_env' => 'testing',
        'reason'     => 'local scoped block',
    ]);

    Http::fake([
        'master.example.com/watchtower/sync/blocks' => Http::response([
            'data' => [
                ['ip' => '1.2.3.4', 'reason' => 'synced', 'source_env' => 'production', 'expires_at' => null, 'blocked_by' => null, 'log_entry_id' => null],
            ],
        ], 200),
    ]);

    $this->artisan('watchtower:sync')->assertSuccessful();

    // The pull path writes with updateOrCreate on (ip, scope). Without the
    // scope in the match it would find the local `auth` row and overwrite it,
    // turning a block on the login routes into an app-wide one — a scoped
    // block silently becoming global is the worst thing scopes could do.
    $scoped = BlacklistedIp::where('ip', '1.2.3.4')->where('scope', 'auth')->first();

    expect($scoped)->not->toBeNull()
        ->and($scoped->reason)->toBe('local scoped block')
        ->and($scoped->source)->toBe(BlockSource::Manual);

    $this->assertDatabaseHas('blacklisted_ips', ['ip' => '1.2.3.4', 'scope' => '', 'source' => 'sync']);
});

it('refuses a second global row for one address', function () {
    BlacklistedIp::create(['ip' => '1.2.3.4', 'source' => BlockSource::Manual, 'source_env' => 'testing']);

    // The unique index moved from (ip) to (ip, scope). It still has to stop
    // two global rows for one address — which a NULLable scope would not,
    // since every engine treats NULLs as distinct in a unique index.
    expect(fn () => BlacklistedIp::create(['ip' => '1.2.3.4', 'source' => BlockSource::Manual, 'source_env' => 'testing']))
        ->toThrow(QueryException::class);
});

it('never writes a block for an address this environment whitelists', function () {
    // The satellite's own never_block list, not the master's. Before #38 the
    // pull path went straight to updateOrCreate() and never consulted it, so
    // a whitelisted address got a row and a cache entry here — while
    // config/watchtower.php promised never_block covers a block arriving "by
    // any means — UI, auto-block, or sync".
    config()->set('watchtower.never_block', ['9.9.9.9']);

    Http::fake([
        'master.example.com/watchtower/sync/blocks' => Http::response([
            'data' => [
                ['ip' => '9.9.9.9', 'reason' => 'blocked on the master', 'source_env' => 'production', 'expires_at' => null, 'blocked_by' => null, 'log_entry_id' => null],
                ['ip' => '1.2.3.4', 'reason' => 'synced', 'source_env' => 'production', 'expires_at' => null, 'blocked_by' => null, 'log_entry_id' => null],
            ],
        ], 200),
    ]);

    $this->artisan('watchtower:sync')
        ->assertSuccessful()
        ->expectsOutputToContain('1 refused by never_block');

    $this->assertDatabaseMissing('blacklisted_ips', ['ip' => '9.9.9.9']);
    $this->assertDatabaseHas('blacklisted_ips', ['ip' => '1.2.3.4', 'source' => 'sync']);

    expect((new BlacklistCache)->isBlocked('9.9.9.9'))->toBeFalse();
});

it('does not let a synced record downgrade a local manual block', function () {
    BlacklistedIp::create([
        'ip'         => '1.2.3.4',
        'reason'     => 'blocked here by hand',
        'source'     => BlockSource::Manual,
        'source_env' => 'staging',
    ]);

    Http::fake([
        'master.example.com/watchtower/sync/blocks' => Http::response([
            'data' => [
                ['ip' => '1.2.3.4', 'reason' => 'from the master', 'source_env' => 'production', 'expires_at' => null, 'blocked_by' => null, 'log_entry_id' => null],
            ],
        ], 200),
    ]);

    $this->artisan('watchtower:sync')
        ->assertSuccessful()
        ->expectsOutputToContain('1 skipped');

    $this->assertDatabaseHas('blacklisted_ips', [
        'ip'     => '1.2.3.4',
        'source' => 'manual',
        'reason' => 'blocked here by hand',
    ]);
});

it('announces nothing for the blocks it pulls', function () {
    Event::fake([IpBlocked::class]);

    Http::fake([
        'master.example.com/watchtower/sync/blocks' => Http::response([
            'data' => [
                ['ip' => '1.2.3.4', 'reason' => 'synced', 'source_env' => 'production', 'expires_at' => null, 'blocked_by' => null, 'log_entry_id' => null],
            ],
        ], 200),
    ]);

    $this->artisan('watchtower:sync')->assertSuccessful();

    // Each block is announced once, by the environment that received it —
    // the webhook contract in the README. A satellite firing IpBlocked for
    // what it pulls would post its whole inherited blocklist on first sync.
    Event::assertNotDispatched(IpBlocked::class);
});

it('rebuilds the cache once for the run, not once per record', function () {
    $cache = new class extends BlacklistCache
    {
        public int $rebuilds = 0;

        public int $writes = 0;

        public function rebuild(): bool
        {
            $this->rebuilds++;

            return parent::rebuild();
        }

        public function write(BlacklistedIp $block): void
        {
            $this->writes++;

            parent::write($block);
        }
    };

    $this->app->instance(BlacklistCache::class, $cache);

    // Ranges, because BlacklistCache::write() pays for a full rebuild on one
    // — a per-record write here would be a rebuild per range, on a list that
    // is the master's entire blocklist.
    Http::fake([
        'master.example.com/watchtower/sync/blocks' => Http::response([
            'data' => [
                ['ip' => '10.0.0.0/8', 'reason' => 'synced', 'source_env' => 'production', 'expires_at' => null, 'blocked_by' => null, 'log_entry_id' => null],
                ['ip' => '172.16.0.0/12', 'reason' => 'synced', 'source_env' => 'production', 'expires_at' => null, 'blocked_by' => null, 'log_entry_id' => null],
                ['ip' => '1.2.3.4', 'reason' => 'synced', 'source_env' => 'production', 'expires_at' => null, 'blocked_by' => null, 'log_entry_id' => null],
            ],
        ], 200),
    ]);

    $this->artisan('watchtower:sync')->assertSuccessful();

    expect($cache->rebuilds)->toBe(1)
        ->and($cache->writes)->toBe(0);
});
