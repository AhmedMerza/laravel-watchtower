<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Queue;
use LogScope\Http\Middleware\Authorize;
use Watchtower\Enums\BlockSource;
use Watchtower\Events\IpBlocked;
use Watchtower\Models\BlacklistedIp;
use Watchtower\Services\BlacklistCache;
use Watchtower\Support\BlockFilters;

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
    $this->withoutMiddleware(Authorize::class);
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

it('returns 500, not the never-block 422, when the block cannot be written', function () {
    config()->set('app.debug', false);
    failBlacklistInserts();

    $response = $this->postJson('/logscope/watchtower/api/block', ['ip' => '10.0.0.1']);

    $response->assertStatus(500);
    // A QueryException's message carries the SQL and its bindings.
    expect($response->getContent())->not->toContain('blacklisted_ips');
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

describe('the block list', function () {
    // A row per call, so a test can say how many blocks exist without
    // repeating the same five keys each time.
    $make = function (array $attributes = []): BlacklistedIp {
        static $n = 0;
        $n++;

        return BlacklistedIp::create($attributes + [
            'ip'         => "10.0.0.{$n}",
            'source'     => BlockSource::Manual,
            'source_env' => 'testing',
        ]);
    };

    it('lists active blocks', function () use ($make) {
        $make();
        $make(['source' => BlockSource::Auto]);

        $this->getJson('/logscope/watchtower/api/blocks')
            ->assertOk()
            ->assertJsonCount(2, 'data')
            ->assertJsonPath('total', 2);
    });

    it('does not return expired blocks', function () use ($make) {
        $make(['expires_at' => now()->subHour()]);
        $make(['expires_at' => now()->addHour()]);

        $this->getJson('/logscope/watchtower/api/blocks')
            ->assertOk()
            ->assertJsonCount(1, 'data')
            ->assertJsonPath('total', 1);
    });

    it('paginates rather than returning every block at once', function () use ($make) {
        foreach (range(1, 30) as $ignored) {
            $make();
        }

        // 30 rows, a 25-row default page: the second page holds the rest.
        $this->getJson('/logscope/watchtower/api/blocks')
            ->assertOk()
            ->assertJsonCount(25, 'data')
            ->assertJsonPath('total', 30)
            ->assertJsonPath('per_page', 25)
            ->assertJsonPath('current_page', 1)
            ->assertJsonPath('last_page', 2);

        $this->getJson('/logscope/watchtower/api/blocks?page=2')
            ->assertOk()
            ->assertJsonCount(5, 'data')
            ->assertJsonPath('current_page', 2);
    });

    it('lets a caller choose the page size', function () use ($make) {
        $make();
        $make();
        $make();

        $this->getJson('/logscope/watchtower/api/blocks?per_page=2')
            ->assertOk()
            ->assertJsonCount(2, 'data')
            ->assertJsonPath('per_page', 2)
            ->assertJsonPath('total', 3);
    });

    it('caps the page size, so per_page cannot restore the unbounded query', function () use ($make) {
        $make();

        $this->getJson('/logscope/watchtower/api/blocks?per_page=100000')
            ->assertOk()
            ->assertJsonPath('per_page', 100);
    });

    it('falls back to the default page size rather than erroring on a junk per_page', function () use ($make) {
        $make();

        foreach (['abc', '0', '-5', ''] as $junk) {
            $this->getJson('/logscope/watchtower/api/blocks?per_page='.$junk)
                ->assertOk()
                ->assertJsonPath('per_page', 25);
        }
    });

    it('filters by source', function () use ($make) {
        $make();
        $make(['source' => BlockSource::Auto]);
        $make(['source' => BlockSource::Auto]);

        $this->getJson('/logscope/watchtower/api/blocks?source=auto')
            ->assertOk()
            ->assertJsonCount(2, 'data')
            ->assertJsonPath('total', 2);
    });

    it('filters by state', function () use ($make) {
        $make(['expires_at' => now()->subHour()]);
        $make(['expires_at' => now()->subDay()]);
        $make();

        $this->getJson('/logscope/watchtower/api/blocks?state=expired')
            ->assertOk()
            ->assertJsonPath('total', 2);

        $this->getJson('/logscope/watchtower/api/blocks?state=all')
            ->assertOk()
            ->assertJsonPath('total', 3);
    });

    it('combines the source and state filters', function () {
        BlacklistedIp::create(['ip' => '10.1.0.1', 'source' => BlockSource::Auto, 'source_env' => 'testing', 'expires_at' => now()->subHour()]);
        BlacklistedIp::create(['ip' => '10.1.0.2', 'source' => BlockSource::Auto, 'source_env' => 'testing', 'expires_at' => now()->subDay()]);
        BlacklistedIp::create(['ip' => '10.1.0.3', 'source' => BlockSource::Manual, 'source_env' => 'testing', 'expires_at' => now()->subHour()]);
        BlacklistedIp::create(['ip' => '10.1.0.4', 'source' => BlockSource::Auto, 'source_env' => 'testing']);
        BlacklistedIp::create(['ip' => '10.1.0.5', 'source' => BlockSource::Manual, 'source_env' => 'testing']);

        $response = $this->getJson('/logscope/watchtower/api/blocks?source=auto&state=expired');

        // The addresses, not the count: dropping either filter returns a
        // different set, but not always a differently sized one.
        $response->assertOk();
        expect($response->json('data.*.ip'))->toEqualCanonicalizing(['10.1.0.1', '10.1.0.2']);
    });

    // The management page's own rule, now shared: a hand-edited query string
    // shouldn't be an error page on the tool you reach for when something is
    // wrong, so an unreadable filter lists active blocks instead of 422ing.
    it('ignores an unrecognised filter rather than refusing the request', function () use ($make) {
        $make();
        $make(['expires_at' => now()->subHour()]);

        $this->getJson('/logscope/watchtower/api/blocks?source=nonsense&state=nonsense')
            ->assertOk()
            ->assertJsonPath('total', 1);
    });

    // The is_string() guard in BlockFilters is load-bearing, not defensive
    // decoration: without it an array reaches where('source', [...]) and the
    // request 500s. A query string is attacker-shaped input on an endpoint
    // whose whole job is answering questions about attackers.
    it('survives an array where a filter should be', function () use ($make) {
        $make();

        foreach (['source[]=auto', 'state[]=all'] as $query) {
            $this->getJson('/logscope/watchtower/api/blocks?'.$query)->assertOk();
        }

        // Not just "doesn't 500": (int) on a non-empty array is 1, so an
        // unguarded cast turns this into one row per page rather than the
        // default perPage()'s docblock promises.
        $this->getJson('/logscope/watchtower/api/blocks?per_page[]=5')
            ->assertOk()
            ->assertJsonPath('per_page', 25);
    });

    it('pages through rows that tie on created_at without dropping or repeating one', function () use ($make) {
        foreach (range(1, 12) as $ignored) {
            $make();
        }

        // Every row in the same second. created_at is second-resolution and a
        // sync push or an auto-block burst writes a batch inside one, so this
        // is the ordinary case rather than a contrived one.
        //
        // This asserts paging stays complete; it does NOT prove the tiebreaker,
        // because SQLite happens to return tied rows in rowid order and so
        // passes without it. The guarantee itself is pinned by the next test,
        // which reads the order clauses rather than trusting one driver.
        BlacklistedIp::query()->update(['created_at' => now()->subMinute()]);

        $seen = [];

        foreach ([1, 2, 3] as $page) {
            $seen = array_merge($seen, $this->getJson(
                '/logscope/watchtower/api/blocks?per_page=5&page='.$page
            )->assertOk()->json('data.*.ip'));
        }

        expect($seen)->toHaveCount(12)
            ->and(array_unique($seen))->toHaveCount(12);
    });

    // Guards the drift between the vocabulary BlockFilters accepts and the
    // arms scopeFilter actually implements: a state added to STATES with no
    // matching arm falls through to `active`, and would otherwise look like a
    // working filter that silently ignores what it was asked for.
    // MySQL and Postgres give no order at all among rows tied on the sort
    // column, so a page boundary landing inside a tied group can repeat a row
    // or skip one. SQLite can't demonstrate that — it orders ties by rowid —
    // so the guarantee is asserted where it's driver-independent: the clauses.
    it('breaks created_at ties on the ULID, so paging is deterministic on any driver', function () {
        expect(BlacklistedIp::query()->latestFirst()->getQuery()->orders)->toBe([
            ['column' => 'created_at', 'direction' => 'desc'],
            ['column' => 'id', 'direction' => 'desc'],
        ]);
    });

    it('gives every state in BlockFilters::STATES its own meaning', function () use ($make) {
        // Three distinct totals. Equal ones would let a state that silently
        // fell through to `active` match the count it was supposed to differ
        // from, and the fixture rather than the assertion would be deciding.
        $make(['expires_at' => now()->subHour()]);
        $make(['expires_at' => now()->subDay()]);
        $make();

        $totals = [];

        foreach (BlockFilters::STATES as $state) {
            $totals[$state] = $this->getJson('/logscope/watchtower/api/blocks?state='.$state)
                ->assertOk()->json('total');
        }

        expect($totals)->toBe(['active' => 1, 'expired' => 2, 'all' => 3])
            ->and(BlockFilters::STATES)->toHaveCount(3);
    });

    it('keeps the filters on the pagination links', function () use ($make) {
        foreach (range(1, 3) as $ignored) {
            $make(['source' => BlockSource::Auto]);
        }

        $response = $this->getJson('/logscope/watchtower/api/blocks?source=auto&per_page=2');

        $response->assertOk();
        expect($response->json('next_page_url'))
            ->toContain('source=auto')
            ->toContain('per_page=2');
    });
});

describe('ranges', function () {
    it('blocks a CIDR range', function (string $ip, string $stored) {
        $this->postJson('/logscope/watchtower/api/block', ['ip' => $ip])
            ->assertOk()
            ->assertJsonPath('data.ip', $stored);
    })->with([
        'IPv4'              => ['203.0.113.0/24', '203.0.113.0/24'],
        'IPv6'              => ['2001:db8::/48', '2001:db8::/48'],
        'host bits set'     => ['203.0.113.9/24', '203.0.113.0/24'],
        'single IPv6 → /64' => ['2001:db8::1', '2001:db8::/64'],
    ]);

    it('refuses a range broader than /16 or /32 without force', function (string $ip) {
        $this->postJson('/logscope/watchtower/api/block', ['ip' => $ip])
            ->assertStatus(422)
            ->assertJsonValidationErrors(['ip' => 'force=true']);

        $this->assertDatabaseCount('blacklisted_ips', 0);
    })->with(['10.0.0.0/15', '2001:d00::/31']);

    it('blocks a broad range when force is sent', function () {
        $this->postJson('/logscope/watchtower/api/block', ['ip' => '10.0.0.0/8', 'force' => true])
            ->assertOk()
            ->assertJsonPath('data.ip', '10.0.0.0/8');
    });

    it('refuses something that is not an IP or range', function (mixed $ip) {
        $this->postJson('/logscope/watchtower/api/block', ['ip' => $ip])
            ->assertStatus(422)
            ->assertJsonValidationErrors('ip');
    })->with(['10.0.0.0/33', '10.0.0.0/1a', 'example.com', 123]);

    it('unblocks a range by its CIDR in the path', function (string $path) {
        $this->postJson('/logscope/watchtower/api/block', ['ip' => '203.0.113.0/24'])->assertOk();

        $this->deleteJson('/logscope/watchtower/api/block/'.$path)
            ->assertOk()
            ->assertJsonPath('deleted', true);

        $this->assertDatabaseCount('blacklisted_ips', 0);
    })->with([
        'slash'   => ['203.0.113.0/24'],
        'encoded' => ['203.0.113.0%2F24'],
    ]);

    it('reports the range that blocks an IP', function () {
        $this->postJson('/logscope/watchtower/api/block', ['ip' => '203.0.113.0/24'])->assertOk();

        $this->getJson('/logscope/watchtower/api/status/203.0.113.9')
            ->assertOk()
            ->assertJsonPath('blocked', true)
            ->assertJsonPath('data.ip', '203.0.113.0/24');
    });

    it('refuses an IP containing a NUL byte with a 422, not a 500', function () {
        // inet_pton() throws on a NUL byte, and `@` doesn't suppress that.
        // It has to sit inside the string: TrimStrings strips a trailing one.
        $this->postJson('/logscope/watchtower/api/block', ['ip' => "1.2.3\u{0000}.4"])
            ->assertStatus(422)
            ->assertJsonValidationErrors('ip');
    });

    it('reports a never-block address covered by a blocked range as unblocked', function () {
        config()->set('watchtower.never_block', ['203.0.113.9']);
        $this->postJson('/logscope/watchtower/api/block', ['ip' => '203.0.113.0/24'])->assertOk();

        $this->getJson('/logscope/watchtower/api/status/203.0.113.9')
            ->assertOk()
            ->assertJsonPath('blocked', false);
    });

    it('reports a range covered by a wider blocked range', function () {
        $this->postJson('/logscope/watchtower/api/block', ['ip' => '203.0.113.0/24'])->assertOk();

        $this->getJson('/logscope/watchtower/api/status/203.0.113.0%2F25')
            ->assertOk()
            ->assertJsonPath('blocked', true)
            ->assertJsonPath('data.ip', '203.0.113.0/24');
    });

    it('reports an expired range as unblocked', function () {
        BlacklistedIp::create([
            'ip'         => '203.0.113.0/24',
            'source'     => BlockSource::Manual,
            'source_env' => 'testing',
            'expires_at' => now()->subMinute(),
        ]);

        $this->getJson('/logscope/watchtower/api/status/203.0.113.0%2F24')
            ->assertOk()
            ->assertJsonPath('blocked', false)
            ->assertJsonPath('data.ip', '203.0.113.0/24');
    });

    it('reports the status of a range', function () {
        $this->postJson('/logscope/watchtower/api/block', ['ip' => '203.0.113.0/24'])->assertOk();

        $this->getJson('/logscope/watchtower/api/status/203.0.113.0%2F24')
            ->assertOk()
            ->assertJsonPath('blocked', true)
            ->assertJsonPath('data.ip', '203.0.113.0/24');

        $this->getJson('/logscope/watchtower/api/status/198.51.100.0%2F24')
            ->assertOk()
            ->assertJsonPath('blocked', false)
            ->assertJsonPath('data', null);
    });
});
