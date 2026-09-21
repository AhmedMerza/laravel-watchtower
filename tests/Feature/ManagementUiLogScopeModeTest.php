<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Queue;
use Illuminate\Support\Facades\Route;
use LogScope\Http\Middleware\Authorize;
use LogScope\LogScopeServiceProvider;
use Watchtower\Enums\BlockSource;
use Watchtower\Models\BlacklistedIp;
use Watchtower\Tests\TestCase;

/**
 * The page in LogScope-integrated mode.
 *
 * It mounts here too, on purpose: LogScope's own UI acts on one address at a
 * time from a log entry and has no list of what is currently blocked, so an
 * install with LogScope would otherwise have no way to see the blocklist.
 */
beforeAll(function () {
    TestCase::$beforeBoot = function ($app) {
        // Watchtower mounts in LogScope mode on class_exists alone, but the
        // log entry link only appears when LogScope's own routes are mounted
        // too. In a real install its auto-discovered provider does that; here
        // nothing registers it, and a provider has to be in place before the
        // app boots — which is what $beforeBoot is for.
        $app->register(LogScopeServiceProvider::class);
    };
});

afterAll(function () {
    TestCase::$beforeBoot = null;
});

beforeEach(function () {
    Event::fake();
    Queue::fake();

    $this->withoutMiddleware(Authorize::class);
});

it('mounts under LogScope\'s prefix and authorization', function () {
    $route = Route::getRoutes()->getByName('watchtower.ui.index');

    expect($route->uri())->toBe('logscope/watchtower')
        ->and($route->gatherMiddleware())->toContain(Authorize::class);
});

it('lists the blocks', function () {
    BlacklistedIp::create([
        'ip'         => '10.0.0.1',
        'reason'     => 'Brute force',
        'source'     => BlockSource::Manual,
        'source_env' => 'testing',
    ]);

    $this->get('/logscope/watchtower')
        ->assertOk()
        ->assertSee('10.0.0.1')
        ->assertSee('Brute force');
});

it('links a block back to the log entry it came from', function () {
    BlacklistedIp::create([
        'ip'           => '10.0.0.1',
        'source'       => BlockSource::Auto,
        'source_env'   => 'testing',
        'log_entry_id' => '01JD8Z1Q0000000000000000AA',
    ]);

    // LogScope deep-links a single entry with ?log=<id> on its index page.
    $this->get('/logscope/watchtower')
        ->assertOk()
        ->assertSee('View log entry')
        ->assertSee('?log=01JD8Z1Q0000000000000000AA', escape: false);
});
