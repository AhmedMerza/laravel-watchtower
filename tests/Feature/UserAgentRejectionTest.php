<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Route;
use Watchtower\Enums\BlockSource;

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
