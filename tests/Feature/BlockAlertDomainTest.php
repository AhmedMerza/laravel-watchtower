<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Notification;
use Watchtower\Enums\BlockSource;
use Watchtower\Notifications\BlockAlert;
use Watchtower\Services\BlacklistService;
use Watchtower\Tests\TestCase;

// The UI routes are registered at boot, so the domain has to be in config
// before the provider boots. Both keys: which one applies depends on whether
// LogScope is installed.
beforeAll(function () {
    TestCase::$beforeBoot = function ($app) {
        $app['config']->set('logscope.routes.domain', '{tenant}.example.com');
        $app['config']->set('watchtower.routes.domain', '{tenant}.example.com');
    };
});

afterAll(function () {
    TestCase::$beforeBoot = null;
});

it('still sends the alert, without a link, when the UI domain has a parameter it cannot fill', function () {
    config()->set('watchtower.notifications.alerts', [
        'enabled'          => true,
        'routes'           => ['mail' => 'ops@example.com'],
        'throttle_minutes' => 60,
        'max_per_window'   => 20,
    ]);
    Notification::fake();

    app(BlacklistService::class)->block('198.51.100.1', ['reason' => 'test', 'source' => BlockSource::Auto]);

    Notification::assertSentOnDemand(BlockAlert::class, fn (BlockAlert $a) => $a->alert['url'] === null);
});
