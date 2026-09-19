<?php

declare(strict_types=1);

use Illuminate\Cache\Events\KeyForgotten;
use Illuminate\Cache\Events\KeyWritten;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Route;
use Watchtower\Enums\BlockSource;
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
