<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Route;
use Watchtower\Tests\TestCase;

// SignalDetectorMiddleware is spliced into the stack at BOOT, and only when a
// request-reading detector is already enabled — so arming response_bursts
// with config()->set() inside a test leaves it out of the stack entirely and
// every assertion here would pass for the wrong reason. It has to be on
// before the app comes up, which is what $beforeBoot does and a beforeEach()
// cannot.

beforeAll(function () {
    TestCase::$beforeBoot = function ($app) {
        $app['config']->set('watchtower.auto_block.enabled', true);
        $app['config']->set('watchtower.auto_block.mode', 'block');
        $app['config']->set('watchtower.auto_block.detectors.response_bursts.enabled', true);
        $app['config']->set('watchtower.auto_block.detectors.response_bursts.count', 3);
    };
});

afterAll(function () {
    TestCase::$beforeBoot = null;
});

beforeEach(function () {
    Route::get('/watchtower-test', fn () => 'ok');

    $this->sqlmap = 'sqlmap/1.8.2#stable (https://sqlmap.org)';
});

it('does not feed its own rejections to the response-burst detector', function () {
    // response_bursts reads the status in terminate(), which Laravel runs on
    // every global middleware whether or not the pipeline short-circuited.
    // Disguising blocks as 404s is something the config suggests, and without
    // the BlockResponse::ANSWERED marker every User-Agent rejection would
    // land in the burst counter — blocking the address through a detector
    // tuned for organic 404s, with bad_user_agent switched off.
    config()->set('watchtower.block_response.status', 404);

    foreach (range(1, 6) as $ignored) {
        $this->withServerVariables(['REMOTE_ADDR' => '203.0.113.36'])
            ->withHeaders(['User-Agent' => $this->sqlmap])
            ->get('/watchtower-test')
            ->assertNotFound();
    }

    $this->assertDatabaseCount('blacklisted_ips', 0);
});

it('still counts a genuine 404 burst while the filter is on', function () {
    // The other half: the marker must not switch the detector off for
    // responses the app really did produce.
    foreach (range(1, 3) as $i) {
        $this->withServerVariables(['REMOTE_ADDR' => '203.0.113.37'])
            ->withHeaders(['User-Agent' => 'curl/8.5.0'])
            ->get("/nothing-here-{$i}");
    }

    $this->assertDatabaseHas('blacklisted_ips', ['ip' => '203.0.113.37']);
});
