<?php

declare(strict_types=1);

use Illuminate\Auth\Events\Failed;
use Illuminate\Cache\ArrayStore;
use Illuminate\Cache\Events\KeyForgotten;
use Illuminate\Cache\Events\KeyWritten;
use Illuminate\Contracts\Http\Kernel;
use Illuminate\Foundation\Auth\User;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Route;
use Watchtower\Enums\BlockSource;
use Watchtower\Http\Middleware\SignalDetectorMiddleware;
use Watchtower\Services\BlacklistCache;
use Watchtower\Tests\TestCase;

// The request detectors are wired at boot — the middleware is only added to
// the stack when one of them is enabled — so they have to be switched on
// before the provider boots, not in a beforeEach.
beforeAll(function () {
    TestCase::$beforeBoot = function ($app) {
        $app['config']->set('cache.default', 'array');
        $app['config']->set('watchtower.cache.store', 'array');
        $app['config']->set('watchtower.auto_block.enabled', true);
        $app['config']->set('watchtower.auto_block.mode', 'block');

        foreach (['failed_logins', 'login_lockouts', 'scanner_paths', 'response_bursts'] as $detector) {
            $app['config']->set("watchtower.auto_block.detectors.{$detector}.enabled", true);
        }
    };
});

afterAll(function () {
    TestCase::$beforeBoot = null;
});

it('blocks a scanner probe within the same request cycle', function () {
    // No route for /.env: the detector runs in global middleware, so it
    // catches paths the app doesn't route at all — which is the whole
    // point, since a 404 is invisible to a log-based rule.
    $this->withServerVariables(['REMOTE_ADDR' => '203.0.113.5'])
        ->get('/.env')
        ->assertForbidden();

    // Blocked on the way in, not on the next request.
    $this->assertDatabaseHas('blacklisted_ips', [
        'ip'     => '203.0.113.5',
        'source' => BlockSource::Auto->value,
    ]);
});

it('matches a scanner pattern through its encoded form', function () {
    $this->withServerVariables(['REMOTE_ADDR' => '203.0.113.15'])
        ->get('/%2Eenv')
        ->assertForbidden();

    $this->assertDatabaseHas('blacklisted_ips', ['ip' => '203.0.113.15']);
});

it('adds no cache writes for a request that matches no detector', function () {
    Route::get('/harmless', fn () => 'ok');

    // Warm the blocklist first: the writes a cold cache makes belong to the
    // warm-up, not to the request, and would otherwise be counted here.
    app(BlacklistCache::class)->rebuild();

    $writes = [];
    Event::listen(
        [KeyWritten::class, KeyForgotten::class],
        function ($event) use (&$writes): void {
            $writes[] = $event->key;
        },
    );

    $this->withServerVariables(['REMOTE_ADDR' => '203.0.113.6'])
        ->get('/harmless')
        ->assertOk();

    // Every detector above is enabled; none of them matched, so none of
    // them may have touched the cache.
    expect($writes)->toBe([]);

    // Prove the listener can see a write at all, so the assertion above
    // can't pass merely because nothing was ever being observed.
    $this->withServerVariables(['REMOTE_ADDR' => '203.0.113.6'])
        ->get('/.env')
        ->assertForbidden();

    expect($writes)->not->toBe([]);
});

it('blocks an address that bursts 404s', function () {
    config()->set('watchtower.auto_block.detectors.response_bursts.count', 3);

    foreach (range(1, 3) as $i) {
        $this->withServerVariables(['REMOTE_ADDR' => '203.0.113.7'])
            ->get("/not-a-route-{$i}")
            ->assertNotFound();
    }

    $this->assertDatabaseHas('blacklisted_ips', [
        'ip'     => '203.0.113.7',
        'source' => BlockSource::Auto->value,
    ]);
});

it('does not count a response outside the configured statuses', function () {
    config()->set('watchtower.auto_block.detectors.response_bursts.count', 2);

    Route::get('/fine', fn () => 'ok');

    foreach (range(1, 4) as $i) {
        $this->withServerVariables(['REMOTE_ADDR' => '203.0.113.11'])
            ->get('/fine')
            ->assertOk();
    }

    $this->assertDatabaseMissing('blacklisted_ips', ['ip' => '203.0.113.11']);
});

it('does not count a 404 or 429 on an excepted path, whatever its case or encoding', function () {
    config()->set('watchtower.auto_block.detectors.response_bursts.count', 1);
    config()->set('watchtower.auto_block.detectors.response_bursts.except_paths', ['/lookup/*']);

    Route::get('/lookup/busy', fn () => abort(429));

    foreach (['/lookup/a', '/LOOKUP/b', '/%6Cookup/c', '/lookup/busy'] as $path) {
        $this->withServerVariables(['REMOTE_ADDR' => '203.0.113.12'])->get($path);
    }

    $this->assertDatabaseMissing('blacklisted_ips', ['ip' => '203.0.113.12']);
});

it('still counts a 404 on a path the except list does not name', function () {
    config()->set('watchtower.auto_block.detectors.response_bursts.count', 2);
    config()->set('watchtower.auto_block.detectors.response_bursts.except_paths', ['/lookup/*']);

    foreach (['/lookups', '/other/lookup/a'] as $path) {
        $this->withServerVariables(['REMOTE_ADDR' => '203.0.113.13'])
            ->get($path)
            ->assertNotFound();
    }

    $this->assertDatabaseHas('blacklisted_ips', ['ip' => '203.0.113.13']);
});

it('warn mode reports the scanner probe instead of blocking it', function () {
    config()->set('watchtower.auto_block.mode', 'warn');

    $logChannel = Mockery::mock()->shouldIgnoreMissing();
    $logChannel->shouldReceive('warning')
        ->once()
        ->withArgs(function (string $message, array $context): bool {
            return $message === 'Watchtower: would-have-blocked (auto-block did not block)'
                && $context['would_have_blocked'] === true
                && $context['ip'] === '203.0.113.8'
                && $context['detector'] === 'scanner_paths'
                && $context['not_blocked_because'] === 'warn mode'
                && $context['user_ids'] === []
                && str_contains($context['hint'], 'WATCHTOWER_AUTO_BLOCK_MODE=block');
        });
    Log::shouldReceive('channel')->andReturn($logChannel);

    // Warn mode means the probe is answered normally — nothing was blocked,
    // so there is nothing to turn it away with.
    $this->withServerVariables(['REMOTE_ADDR' => '203.0.113.8'])
        ->get('/.env')
        ->assertNotFound();

    $this->assertDatabaseMissing('blacklisted_ips', ['ip' => '203.0.113.8']);
});

it('registers the detector middleware when a request detector is enabled', function () {
    // The mirror of DetectorMiddlewareRegistrationTest, which asserts it is
    // absent under the shipped defaults.
    expect(app(Kernel::class)->getGlobalMiddleware())
        ->toContain(SignalDetectorMiddleware::class);
});

it('ignores a detector switched off even while its sibling keeps the middleware in the stack', function () {
    // response_bursts stays on, so the middleware is registered; scanner_paths
    // is off, so it must do nothing. Without this, "off" is only ever tested
    // by the middleware being absent entirely.
    config()->set('watchtower.auto_block.detectors.scanner_paths.enabled', false);

    $this->withServerVariables(['REMOTE_ADDR' => '203.0.113.31'])
        ->get('/.env')
        ->assertNotFound();

    $this->assertDatabaseMissing('blacklisted_ips', ['ip' => '203.0.113.31']);
});

it('ignores response_bursts when it is switched off', function () {
    config()->set('watchtower.auto_block.detectors.response_bursts.enabled', false);

    foreach (range(1, 5) as $i) {
        $this->withServerVariables(['REMOTE_ADDR' => '203.0.113.32'])
            ->get("/gone-{$i}")
            ->assertNotFound();
    }

    $this->assertDatabaseMissing('blacklisted_ips', ['ip' => '203.0.113.32']);
});

it('lets the request through when the cache backend is down, instead of turning it into a 500', function () {
    // Detection is a layer on top of the app; it is never worth the app. A
    // dead Redis must not turn every 404 and every failed login into an
    // error page.
    Cache::extend('detector-fails', fn () => Cache::repository(new class extends ArrayStore
    {
        public function get($key): mixed
        {
            throw new RuntimeException('cache down');
        }

        public function put($key, $value, $seconds): bool
        {
            throw new RuntimeException('cache down');
        }

        public function add($key, $value, $seconds): bool
        {
            throw new RuntimeException('cache down');
        }

        public function increment($key, $value = 1): bool
        {
            throw new RuntimeException('cache down');
        }
    }));

    config()->set('cache.stores.detector-fails', ['driver' => 'detector-fails']);
    // HitWindow resolves the store per call, so this reaches the counter.
    config()->set('watchtower.cache.store', 'detector-fails');

    Log::shouldReceive('channel')->andReturn(Mockery::mock()->shouldIgnoreMissing());

    $this->withServerVariables(['REMOTE_ADDR' => '203.0.113.33'])
        ->get('/.env')
        ->assertNotFound();

    $this->assertDatabaseMissing('blacklisted_ips', ['ip' => '203.0.113.33']);
});

it('never lets a failed login hand an identity to the shared-IP guard', function () {
    config()->set('watchtower.auto_block.shared_ip_user_threshold', 3);
    config()->set('watchtower.auto_block.detectors.failed_logins.count', 3);

    Route::get('/attempt-login', function () {
        // The event carries the account the credentials were aimed at,
        // exactly as a real guard fires it.
        event(new Failed('web', auth()->user(), ['email' => 'target@example.com']));

        return 'tried';
    });

    foreach ([1, 2, 3] as $id) {
        $user = new User;
        $user->id = $id;

        $this->actingAs($user)
            ->withServerVariables(['REMOTE_ADDR' => '203.0.113.34'])
            ->get('/attempt-login');
    }

    // Three different identities were attached to the three failed logins.
    // If any of them reached the guard it would read 3 distinct users, hit
    // the threshold, and stand the block down — which is how a credential
    // stuffing run would disarm the detector aimed at it. The block must
    // still land.
    $this->assertDatabaseHas('blacklisted_ips', ['ip' => '203.0.113.34']);
});

it('reports a held-back detector once per block it predicts, not once per threshold crossing', function () {
    config()->set('watchtower.auto_block.mode', 'warn');
    config()->set('watchtower.auto_block.detectors.response_bursts.count', 3);

    $logChannel = Mockery::mock()->shouldIgnoreMissing();
    // Nine matching requests at a threshold of three. Closing the window on
    // each crossing bounds this at three; a real block would have stopped the
    // traffic at the first, so the dry run reports once and holds that
    // decision for as long as the block would have run. The distinction is
    // the whole point of warn mode: a line per crossing describes traffic
    // arming would have prevented, and at `count => 1` — which scanner_paths
    // ships — a crossing is every single request.
    $logChannel->shouldReceive('warning')
        ->once()
        ->withArgs(fn (string $m, array $c): bool => ($c['detector'] ?? null) === 'response_bursts');
    Log::shouldReceive('channel')->andReturn($logChannel);

    foreach (range(1, 9) as $i) {
        $this->withServerVariables(['REMOTE_ADDR' => '203.0.113.35'])->get("/absent-{$i}");
    }

    $this->assertDatabaseMissing('blacklisted_ips', ['ip' => '203.0.113.35']);
});

it('reports again once the block it was predicting would have lapsed', function () {
    config()->set('watchtower.auto_block.mode', 'warn');
    config()->set('watchtower.auto_block.block_duration_minutes', 30);

    $logChannel = Mockery::mock()->shouldIgnoreMissing();
    $logChannel->shouldReceive('warning')
        ->twice()
        ->withArgs(fn (string $m, array $c): bool => ($c['detector'] ?? null) === 'scanner_paths');
    Log::shouldReceive('channel')->andReturn($logChannel);

    // Reports, then holds.
    $this->withServerVariables(['REMOTE_ADDR' => '203.0.113.36'])->get('/.env');
    $this->travel(29)->minutes();
    $this->withServerVariables(['REMOTE_ADDR' => '203.0.113.36'])->get('/.env');

    // Past the duration a real block would have carried, the address is back
    // — so the dry run says so again rather than staying quiet for good.
    $this->travel(2)->minutes();
    $this->withServerVariables(['REMOTE_ADDR' => '203.0.113.36'])->get('/.env');
});

it('arms on the very next request rather than serving out the dry run hold', function () {
    config()->set('watchtower.auto_block.mode', 'warn');

    $this->withServerVariables(['REMOTE_ADDR' => '203.0.113.37'])->get('/.env');
    $this->assertDatabaseMissing('blacklisted_ips', ['ip' => '203.0.113.37']);

    // The hold from the dry run is still live. Arming is an operator changing
    // their mind about this exact address, so it must not spend up to
    // block_duration_minutes silently declining to act on it — which is why
    // the hold records the mode it was opened under.
    config()->set('watchtower.auto_block.mode', 'block');

    $this->withServerVariables(['REMOTE_ADDR' => '203.0.113.37'])->get('/.env');
    $this->assertDatabaseHas('blacklisted_ips', ['ip' => '203.0.113.37']);
});

it('holds a never_auto_block address after one refusal, in block mode too', function () {
    config()->set('watchtower.never_auto_block', ['203.0.113.39']);

    $logChannel = Mockery::mock()->shouldIgnoreMissing();
    // never_auto_block is a standing refusal, so nothing ever takes the
    // address away from the detector the way a block does. Every probe used
    // to be refused afresh and write its own line — in block mode as much as
    // in warn, which is why this hold is not conditioned on the mode.
    $logChannel->shouldReceive('warning')
        ->once()
        ->withArgs(fn (string $m, array $c): bool => ($c['not_blocked_because'] ?? null) === 'never_auto_block');
    Log::shouldReceive('channel')->andReturn($logChannel);

    foreach (range(1, 5) as $i) {
        $this->withServerVariables(['REMOTE_ADDR' => '203.0.113.39'])->get('/.env');
    }

    $this->assertDatabaseMissing('blacklisted_ips', ['ip' => '203.0.113.39']);
});
