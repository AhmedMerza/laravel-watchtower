<?php

declare(strict_types=1);

use Illuminate\Foundation\Auth\User;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Route;
use Watchtower\Services\BlacklistCache;
use Watchtower\Tests\Support\CountingStore;
use Watchtower\Tests\TestCase;

/**
 * What a detector signal costs the cache, counted operation by operation.
 *
 * The detector path is paced by whoever is probing, so every avoidable round
 * trip on it is an attacker's lever — see issue #69, which measured ~9-11 for
 * a single scanner probe. These tests pin the sequence rather than a total,
 * so a change that reintroduces one shows up as a readable diff.
 *
 * One store op == one Redis round trip here; CountingStore explains how that
 * is kept true.
 */
beforeAll(function () {
    TestCase::$beforeBoot = function ($app) {
        $app['config']->set('cache.stores.counting', ['driver' => 'counting']);
        $app['config']->set('cache.default', 'counting');
        $app['config']->set('watchtower.cache.store', 'counting');
        $app['config']->set('watchtower.auto_block.enabled', true);
        $app['config']->set('watchtower.auto_block.mode', 'block');
        $app['config']->set('watchtower.auto_block.detectors.scanner_paths.enabled', true);
    };
});

afterAll(function () {
    TestCase::$beforeBoot = null;
});

beforeEach(function () {
    Cache::extend('counting', fn ($app) => Cache::repository(new CountingStore));

    // Warm the blocklist: the reads and writes a cold cache makes belong to
    // the warm-up, not to the request under test.
    app(BlacklistCache::class)->rebuild();

    $this->store = Cache::store('counting')->getStore();
    $this->store->ops = [];
});

it('costs four cache operations for a probe that does not reach its threshold', function () {
    config()->set('watchtower.auto_block.detectors.scanner_paths.count', 5);

    $this->withServerVariables(['REMOTE_ADDR' => '203.0.113.40'])->get('/.env');

    // Two reads to answer "is this address blocked", then two to count the
    // hit. Nothing else — and in particular the blocklist pair appears ONCE.
    // BlockedIpMiddleware stashes its verdict and AutoBlockService reads the
    // stash; before #69 it asked again and this was six.
    expect($this->store->ops)->toBe([
        'get watchtower:blacklist:_ranges',
        'get watchtower:blacklist:ip:203.0.113.40',
        'add watchtower:blacklist:hits:scanner_paths:203.0.113.40',
        'increment watchtower:blacklist:hits:scanner_paths:203.0.113.40',
    ]);
});

it('opens the hit window without a RateLimiter timer key', function () {
    config()->set('watchtower.auto_block.detectors.scanner_paths.count', 5);

    $this->withServerVariables(['REMOTE_ADDR' => '203.0.113.41'])->get('/.env');

    // Laravel's RateLimiter writes a `:timer` sidecar so availableIn() can
    // report a wait. Nothing here ever asks, and it cost a round trip on
    // every hit plus another on every clear.
    expect($this->store->opsMatching(':timer'))->toBe([]);
});

it('skips the user-set delete when the traffic was anonymous', function () {
    config()->set('watchtower.auto_block.detectors.scanner_paths.count', 1);

    $this->withServerVariables(['REMOTE_ADDR' => '203.0.113.42'])->get('/.env');

    // The crossing reads the user set to see who would be caught, then closes
    // the window. Most detector traffic is anonymous and never opened that
    // set, so deleting it would spend a round trip on a key never written.
    expect($this->store->opsMatching(':scanner_paths:'))->toBe([
        'add hits:scanner_paths:203.0.113.42',
        'increment hits:scanner_paths:203.0.113.42',
        'get notional:scanner_paths:203.0.113.42',
        'get users:scanner_paths:203.0.113.42',
        'forget hits:scanner_paths:203.0.113.42',
    ]);
});

it('costs a held address nothing past the hit and the hold it is serving', function () {
    config()->set('watchtower.auto_block.mode', 'warn');
    config()->set('watchtower.auto_block.detectors.scanner_paths.count', 1);

    // The first probe crosses, reports, and opens the notional block.
    $this->withServerVariables(['REMOTE_ADDR' => '203.0.113.44'])->get('/.env');
    $this->store->ops = [];

    // The second pays the counter it was always going to pay, then one read
    // that says "already decided" and ends it. No user read, no close, no log
    // write — the ~4 operations per probe issue #71 measured at ~1,030 a day,
    // which a real block would never have let happen at all.
    $this->withServerVariables(['REMOTE_ADDR' => '203.0.113.44'])->get('/.env');

    expect($this->store->opsMatching(':scanner_paths:'))->toBe([
        'add hits:scanner_paths:203.0.113.44',
        'increment hits:scanner_paths:203.0.113.44',
        'get notional:scanner_paths:203.0.113.44',
    ]);
});

it('still deletes the user set when one was actually opened', function () {
    config()->set('watchtower.auto_block.detectors.scanner_paths.count', 2);

    Route::get('/seen', fn () => 'ok')->middleware('web');

    $user = new class extends User
    {
        protected $table = 'users';

        public function getAuthIdentifier()
        {
            return 7;
        }
    };

    // First probe opens the window and records the signed-in user; the second
    // crosses the threshold and has a set to drop.
    foreach (range(1, 2) as $i) {
        $this->actingAs($user)
            ->withServerVariables(['REMOTE_ADDR' => '203.0.113.43'])
            ->get('/.env');
    }

    // Falsifies the test above: the delete is skipped because the set is
    // empty, not because the code stopped deleting it.
    expect($this->store->opsMatching('users:scanner_paths:203.0.113.43'))
        ->toContain('forget users:scanner_paths:203.0.113.43');
});
