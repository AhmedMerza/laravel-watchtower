<?php

declare(strict_types=1);

use Illuminate\Contracts\Cache\Repository;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Route;
use Watchtower\Enums\BlockSource;
use Watchtower\Http\Middleware\UserAgentMiddleware;

// End-to-end through the real middleware stack, on the shipped defaults:
// the filter is on, and the detector that escalates it is not.

beforeEach(function () {
    Route::get('/watchtower-test', fn () => 'ok');

    $this->sqlmap = 'sqlmap/1.8.2#stable (https://sqlmap.org)';
});

it('rejects a scanner User-Agent on a stock install', function () {
    $this->withServerVariables(['REMOTE_ADDR' => '203.0.113.30'])
        ->withHeaders(['User-Agent' => $this->sqlmap])
        ->get('/watchtower-test')
        ->assertForbidden();
});

it('serves an ordinary client the route', function () {
    $this->withServerVariables(['REMOTE_ADDR' => '203.0.113.31'])
        ->withHeaders(['User-Agent' => 'curl/8.5.0'])
        ->get('/watchtower-test')
        ->assertOk()
        ->assertSee('ok');
});

it('rejects the request without ever blocking the address', function () {
    // The headline safety property: the User-Agent is written by the client,
    // so on its own it rejects requests and nothing more.
    //
    // The engine is deliberately ARMED here, with another detector running.
    // Asserting this on the shipped defaults would prove nothing at all:
    // AutoBlockService::detect() returns early whenever auto_block.enabled
    // is false, so the count would stay at zero however broken the
    // middleware was.
    config()->set('watchtower.auto_block.enabled', true);
    config()->set('watchtower.auto_block.mode', 'block');
    config()->set('watchtower.auto_block.detectors.scanner_paths.enabled', true);

    foreach (range(1, 20) as $ignored) {
        $this->withServerVariables(['REMOTE_ADDR' => '203.0.113.32'])
            ->withHeaders(['User-Agent' => $this->sqlmap])
            ->get('/watchtower-test')
            ->assertForbidden();
    }

    $this->assertDatabaseCount('blacklisted_ips', 0);
});

it('never turns away a never_block address, whatever it claims to be', function () {
    config()->set('watchtower.never_block', ['203.0.113.0/24']);

    $this->withServerVariables(['REMOTE_ADDR' => '203.0.113.33'])
        ->withHeaders(['User-Agent' => $this->sqlmap])
        ->get('/watchtower-test')
        ->assertOk();
});

it('blocks the address once bad_user_agent is armed', function () {
    config()->set('watchtower.auto_block.enabled', true);
    config()->set('watchtower.auto_block.mode', 'block');
    config()->set('watchtower.auto_block.detectors.bad_user_agent.enabled', true);
    config()->set('watchtower.auto_block.detectors.bad_user_agent.count', 3);

    foreach (range(1, 3) as $ignored) {
        $this->withServerVariables(['REMOTE_ADDR' => '203.0.113.34'])
            ->withHeaders(['User-Agent' => $this->sqlmap])
            ->get('/watchtower-test')
            ->assertForbidden();
    }

    $this->assertDatabaseHas('blacklisted_ips', [
        'ip'     => '203.0.113.34',
        'source' => BlockSource::Auto->value,
    ]);
});

it('respects never_auto_block when the detector is armed', function () {
    // Every guard a log rule answers to applies here too, because the
    // rejection is counted through the same AutoBlockService::record().
    config()->set('watchtower.auto_block.enabled', true);
    config()->set('watchtower.auto_block.mode', 'block');
    config()->set('watchtower.auto_block.detectors.bad_user_agent.enabled', true);
    config()->set('watchtower.auto_block.detectors.bad_user_agent.count', 2);
    config()->set('watchtower.never_auto_block', ['203.0.113.35']);

    foreach (range(1, 4) as $ignored) {
        $this->withServerVariables(['REMOTE_ADDR' => '203.0.113.35'])
            ->withHeaders(['User-Agent' => $this->sqlmap])
            ->get('/watchtower-test')
            ->assertForbidden();
    }

    // Still rejected every time — but the address is left alone.
    $this->assertDatabaseCount('blacklisted_ips', 0);
});

// The rejection line is throttled so an attacker's request rate can't set
// the growth of a log sink that stores every line.

function rejectedLines(): array
{
    return array_values(array_filter(
        $GLOBALS['wtUaLog'],
        fn ($l) => $l === 'Watchtower: rejected a request by User-Agent',
    ));
}

function captureRejections(): void
{
    $GLOBALS['wtUaLog'] = [];
    $channel = Mockery::mock();
    $channel->shouldReceive('debug')->andReturnUsing(function ($m) {
        $GLOBALS['wtUaLog'][] = $m;
    });
    Log::shouldReceive('channel')->andReturn($channel);
}

it('logs one rejection line per address and pattern in a window, not one per request', function () {
    captureRejections();

    foreach (range(1, 25) as $ignored) {
        $this->withServerVariables(['REMOTE_ADDR' => '203.0.113.40'])
            ->withHeaders(['User-Agent' => $this->sqlmap])
            ->get('/watchtower-test')
            ->assertForbidden();
    }

    expect(rejectedLines())->toHaveCount(1);

    // A different address is its own window: the operator still sees it.
    $this->withServerVariables(['REMOTE_ADDR' => '203.0.113.41'])
        ->withHeaders(['User-Agent' => $this->sqlmap])
        ->get('/watchtower-test')
        ->assertForbidden();

    expect(rejectedLines())->toHaveCount(2);
});

it('logs again once the window has passed', function () {
    captureRejections();
    $hit = fn () => $this->withServerVariables(['REMOTE_ADDR' => '203.0.113.42'])
        ->withHeaders(['User-Agent' => $this->sqlmap])
        ->get('/watchtower-test')
        ->assertForbidden();

    $hit();
    $this->travel(61)->seconds();
    $hit();

    expect(rejectedLines())->toHaveCount(2);
});

it('still rejects, and writes no line, when the cache errors', function () {
    captureRejections();
    $broken = Mockery::mock(Repository::class);
    $broken->shouldReceive('add')->andThrow(new RuntimeException('cache down'));
    Cache::shouldReceive('store')->andReturn($broken);

    app(UserAgentMiddleware::class)->handle(
        Request::create('/x', 'GET', server: ['REMOTE_ADDR' => '203.0.113.43', 'HTTP_USER_AGENT' => $this->sqlmap]),
        fn () => response('ok'),
    )->getStatusCode() === 403 or throw new RuntimeException('not rejected');

    expect(rejectedLines())->toHaveCount(0);
});
