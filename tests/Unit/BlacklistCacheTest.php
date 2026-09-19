<?php

declare(strict_types=1);

use Carbon\Carbon;
use Illuminate\Cache\ArrayStore;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
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

    $this->cache = new BlacklistCache;
});

function blacklistRow(string $ip, ?Carbon $expiresAt = null): BlacklistedIp
{
    return BlacklistedIp::create([
        'ip'         => $ip,
        'source'     => BlockSource::Manual,
        'source_env' => 'testing',
        'expires_at' => $expiresAt,
    ]);
}

/** Mark the cache warm, as a rebuild would, so a lookup doesn't rebuild it. */
function putRangeList(array $ranges = [], int $ipv6Prefix = 64, bool $partial = false): void
{
    Cache::store('array')->put('watchtower:blacklist:_ranges', array_filter([
        'ipv6_prefix' => $ipv6Prefix,
        'ranges'      => $ranges,
        'expires'     => now()->addHour()->getTimestamp(),
        'partial'     => $partial,
    ], fn ($value) => $value !== false), 3600);
}

/** A cache that serves reads but fails every write, as a full or read-only Redis would. */
function useCacheThatFailsWrites(): void
{
    Cache::extend('fails-writes', fn () => Cache::repository(new class extends ArrayStore
    {
        public function put($key, $value, $seconds)
        {
            throw new RuntimeException('cache write failed');
        }
    }));

    config()->set('cache.stores.fails-writes', ['driver' => 'fails-writes']);
    config()->set('watchtower.cache.store', 'fails-writes');
    test()->cache = new BlacklistCache;
}

it('returns false for an IP not in the cache', function () {
    expect($this->cache->isBlocked('9.9.9.9'))->toBeFalse();
});

it('returns true for a permanently blocked IP (empty string value)', function () {
    putRangeList();
    Cache::store('array')->put('watchtower:blacklist:ip:1.2.3.4', '', 3600);

    expect($this->cache->isBlocked('1.2.3.4'))->toBeTrue();
});

it('returns true for a temporarily blocked IP that has not expired', function () {
    putRangeList();
    $future = now()->addHour()->toIso8601String();
    Cache::store('array')->put('watchtower:blacklist:ip:1.2.3.4', $future, 3600);

    expect($this->cache->isBlocked('1.2.3.4'))->toBeTrue();
});

it('returns false for a temporarily blocked IP that has expired', function () {
    putRangeList();
    $past = now()->subHour()->toIso8601String();
    Cache::store('array')->put('watchtower:blacklist:ip:1.2.3.4', $past, 3600);

    expect($this->cache->isBlocked('1.2.3.4'))->toBeFalse();
});

it('does not rebuild when the range list shows the cache is warm', function () {
    putRangeList();
    Cache::store('array')->put('watchtower:blacklist:ip:198.51.100.1', '', 3600);

    DB::enableQueryLog();

    // No DB row backs this entry, so a rebuild would have forgotten it.
    expect($this->cache->isBlocked('198.51.100.1'))->toBeTrue();
    expect(DB::getQueryLog())->toBeEmpty();

    DB::disableQueryLog();
});

it('warms a cold cache on the first lookup', function () {
    blacklistRow('1.2.3.4');

    expect(Cache::store('array')->has('watchtower:blacklist:_ranges'))->toBeFalse();

    expect($this->cache->isBlocked('1.2.3.4'))->toBeTrue();
    expect(Cache::store('array')->get('watchtower:blacklist:_index'))->toBe(['1.2.3.4']);
    expect(Cache::store('array')->has('watchtower:blacklist:_ranges'))->toBeTrue();
});

it('keeps trying to warm a cache whose range list was written as partial', function () {
    putRangeList(['203.0.113.0/24' => 0], partial: true);

    // The DB has no such range, so a warm-up drops it.
    expect($this->cache->isBlocked('203.0.113.9'))->toBeFalse();
    expect(Cache::store('array')->get('watchtower:blacklist:_ranges'))->not->toHaveKey('partial');
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

it('empties the index when no IPs are blocked on rebuild', function () {
    Cache::store('array')->put('watchtower:blacklist:_index', ['old.ip'], 3600);
    Cache::store('array')->put('watchtower:blacklist:ip:old.ip', '', 3600);

    // No DB rows — rebuild() should clear the stale per-IP entry, but leave
    // an EMPTY range list behind rather than none. isBlocked() reads a
    // missing list as a cold cache, so skipping it here would make every
    // request re-run the rebuild for as long as the blocklist is empty.
    $this->cache->rebuild();

    expect(Cache::store('array')->get('watchtower:blacklist:_index'))->toBe([]);
    expect(Cache::store('array')->get('watchtower:blacklist:_ranges')['ranges'])->toBe([]);
    expect(Cache::store('array')->has('watchtower:blacklist:ip:old.ip'))->toBeFalse();
});

it('stops re-querying the DB once an empty blocklist has been warmed', function () {
    // The steady state of a fresh install: no blocks at all. The first
    // lookup writes the empty range list; every later one must not run
    // another `BlacklistedIp::active()->get()` on the request path.
    expect(BlacklistedIp::count())->toBe(0);

    $this->cache->isBlocked('1.2.3.4');

    expect(Cache::store('array')->has('watchtower:blacklist:_ranges'))->toBeTrue();

    DB::enableQueryLog();
    DB::flushQueryLog();

    $this->cache->isBlocked('1.2.3.4');
    $this->cache->isBlocked('1.2.3.4');

    expect(DB::getQueryLog())->toBeEmpty();

    DB::disableQueryLog();
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

it('ignores a leftover watchtower.cache.connection value without logging', function () {
    // The key was removed in #32 along with its deprecation warning, which a
    // static guard had been re-emitting on every request under PHP-FPM. An
    // upgrader's stale env var must now be inert, not a log line per request.
    config()->set('watchtower.cache.connection', 'legacy-redis-conn');

    Log::shouldReceive('channel')->andReturnSelf();
    Log::shouldNotReceive('warning');

    new BlacklistCache;
    new BlacklistCache;
});

it('answers a lookup when warming the cache fails to write', function () {
    // A missing store throws on the lookup's first read, and the middleware
    // fails open on that. A store that reads but can't write only fails
    // inside the warm-up, which must not take the lookup down with it.
    useCacheThatFailsWrites();
    blacklistRow('1.2.3.4');

    expect($this->cache->isBlocked('1.2.3.4'))->toBeFalse();
});

it('warns once per window, not once per request, while the warm-up fails', function () {
    // Every lookup finds the cache cold until a warm-up succeeds. Without
    // the failure window, a cache outage on a busy app would fill the disk
    // with one line per request.
    useCacheThatFailsWrites();

    Log::shouldReceive('channel')->andReturnSelf();
    Log::shouldReceive('warning')->once();

    $this->cache->isBlocked('1.2.3.4');
    $this->cache->isBlocked('1.2.3.4');
    $this->cache->isBlocked('1.2.3.4');
});

it('warns again once the failure window has passed', function () {
    useCacheThatFailsWrites();

    Log::shouldReceive('channel')->andReturnSelf();
    Log::shouldReceive('warning')->twice();

    $this->cache->isBlocked('1.2.3.4');

    touch(storage_path('framework/watchtower-warm-failure'), time() - 61);

    $this->cache->isBlocked('1.2.3.4');
});

it('stands the warm-up down when the DB read fails, not just the cache', function () {
    // Cache reachable but empty, DB gone: rebuild() logs and swallows, so
    // without asking it for a verdict every lookup would retry.
    Schema::drop('blacklisted_ips');

    Log::shouldReceive('channel')->andReturnSelf();
    Log::shouldReceive('warning')->once();

    $this->cache->isBlocked('1.2.3.4');
    $this->cache->isBlocked('1.2.3.4');
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

describe('ranges', function () {
    it('blocks addresses inside an IPv4 range and lets the rest through', function () {
        blacklistRow('203.0.113.0/24');

        $this->cache->rebuild();

        expect($this->cache->isBlocked('203.0.113.200'))->toBeTrue()
            ->and($this->cache->isBlocked('203.0.114.1'))->toBeFalse()
            ->and($this->cache->isBlocked('203.0.112.255'))->toBeFalse()
            ->and(Cache::store('array')->get('watchtower:blacklist:_ranges')['ranges'])->toBe(['203.0.113.0/24' => 0]);
    });

    it('gives an IPv6 range at the block prefix its own key, off the range list', function () {
        blacklistRow('2001:db8:1:2::/64');

        $this->cache->rebuild();

        expect(Cache::store('array')->get('watchtower:blacklist:ip:2001:db8:1:2::/64'))->toBe('')
            ->and(Cache::store('array')->get('watchtower:blacklist:_ranges')['ranges'])->toBe([])
            ->and($this->cache->isBlocked('2001:db8:1:2:ffff::1'))->toBeTrue()
            ->and($this->cache->isBlocked('2001:db8:1:3::1'))->toBeFalse();
    });

    it('still blocks exactly a bare IPv6 address left from before prefixes', function () {
        blacklistRow('2001:db8::5');

        $this->cache->rebuild();

        expect($this->cache->isBlocked('2001:db8::5'))->toBeTrue()
            ->and($this->cache->isBlocked('2001:db8::6'))->toBeFalse();
    });

    it('gives bare IPv6 addresses their own key when the prefix is 128', function () {
        config()->set('watchtower.ipv6_block_prefix', 128);
        blacklistRow('2001:db8::5');
        blacklistRow('2001:db8:1::/64');

        $this->cache->rebuild();

        expect(Cache::store('array')->get('watchtower:blacklist:ip:2001:db8::5'))->toBe('')
            ->and(Cache::store('array')->get('watchtower:blacklist:_ranges')['ranges'])->toBe(['2001:db8:1::/64' => 0])
            ->and($this->cache->isBlocked('2001:db8::5'))->toBeTrue()
            ->and($this->cache->isBlocked('2001:db8::6'))->toBeFalse()
            ->and($this->cache->isBlocked('2001:db8:1::9'))->toBeTrue();
    });

    it('looks up by the prefix the cache was built for until the next rebuild', function () {
        blacklistRow('2001:db8:1:2::/64');
        $this->cache->rebuild();

        // Looking up by the new prefix would miss the /64 key and let the
        // whole network through until something rebuilt the cache.
        config()->set('watchtower.ipv6_block_prefix', 56);
        expect($this->cache->isBlocked('2001:db8:1:2::9'))->toBeTrue();

        // Rebuilt at /56, the /64 is a range and still doesn't widen.
        $this->cache->rebuild();
        expect($this->cache->isBlocked('2001:db8:1:2::9'))->toBeTrue()
            ->and($this->cache->isBlocked('2001:db8:1:3::1'))->toBeFalse();
    });

    it('lets a temporary range lapse on its own expiry', function () {
        blacklistRow('203.0.113.0/24', now()->addHour());
        $this->cache->rebuild();

        expect($this->cache->isBlocked('203.0.113.9'))->toBeTrue();

        $this->travel(61)->minutes();

        expect($this->cache->isBlocked('203.0.113.9'))->toBeFalse();
    });

    it('skips a malformed row instead of failing the rebuild', function () {
        blacklistRow('not-an-ip');
        blacklistRow('10.0.0.0/33');
        blacklistRow('203.0.113.0/24');

        expect($this->cache->rebuild())->toBeTrue()
            ->and($this->cache->isBlocked('10.0.0.1'))->toBeFalse()
            ->and($this->cache->isBlocked('203.0.113.9'))->toBeTrue();
    });

    it('adds a range without restarting the list\'s expiry', function () {
        $this->cache->rebuild();
        $this->travel(1)->hours();

        $this->cache->put(blacklistRow('203.0.113.0/24'));

        expect($this->cache->isBlocked('203.0.113.9'))->toBeTrue();

        // A restarted expiry would outlive the keys the last rebuild wrote,
        // and lookups would go on trusting a cache that had emptied.
        $this->travel(23)->hours();
        $this->travel(1)->minutes();
        expect(Cache::store('array')->has('watchtower:blacklist:_ranges'))->toBeFalse();
    });

    it('marks the list partial when it adds a range to a cold cache', function () {
        $this->cache->put(new BlacklistedIp(['ip' => '203.0.113.0/24']));

        expect(Cache::store('array')->get('watchtower:blacklist:_ranges'))
            ->toMatchArray(['partial' => true, 'ranges' => ['203.0.113.0/24' => 0]]);
    });

    it('gives a single IP its own key when the rebuild fallback writes it', function () {
        putRangeList();

        $this->cache->put(new BlacklistedIp(['ip' => '1.2.3.4']));

        // A bare IP parked in the range list would still match isBlocked(),
        // so only the key itself shows the O(1) path was taken.
        expect(Cache::store('array')->get('watchtower:blacklist:ip:1.2.3.4'))->toBe('')
            ->and(Cache::store('array')->get('watchtower:blacklist:_ranges')['ranges'])->toBe([]);
    });

    it('leaves a cold cache cold when forgetting a target it never held', function () {
        $this->cache->forget('203.0.113.0/24');

        // Writing a null list here would read as "warm" and stop lookups
        // from rebuilding. unblock() hides this by always rebuilding after.
        expect(Cache::store('array')->has('watchtower:blacklist:_ranges'))->toBeFalse();
    });

    it('forgets a range without a rebuild', function () {
        blacklistRow('203.0.113.0/24');
        $this->cache->rebuild();

        $this->cache->forget('203.0.113.0/24');

        expect($this->cache->isBlocked('203.0.113.9'))->toBeFalse();
    });
});
