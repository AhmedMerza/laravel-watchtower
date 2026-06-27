<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Http;
use Watchtower\Enums\BlockSource;
use Watchtower\Events\IpBlocked;
use Watchtower\Listeners\NotifyOnBlock;
use Watchtower\Models\BlacklistedIp;

beforeEach(function () {
    $this->record = BlacklistedIp::create([
        'ip'         => '1.2.3.4',
        'reason'     => 'test',
        'source'     => BlockSource::Manual,
        'source_env' => 'staging',
    ]);

    $this->event = new IpBlocked($this->record);
    $this->listener = new NotifyOnBlock;
});

it('does nothing when webhook URL is not configured', function () {
    config()->set('watchtower.notifications.webhook_url', null);

    Http::fake();

    $this->listener->handle($this->event);

    Http::assertNothingSent();
});

it('posts to the webhook URL with the correct payload', function () {
    config()->set('watchtower.notifications.webhook_url', 'https://hooks.example.com/notify');

    Http::fake([
        'hooks.example.com/notify' => Http::response([], 200),
    ]);

    $this->listener->handle($this->event);

    Http::assertSent(function ($request) {
        return $request->url() === 'https://hooks.example.com/notify'
            && $request['ip'] === '1.2.3.4'
            && $request['reason'] === 'test'
            && $request['source'] === 'manual'
            && $request['source_env'] === 'staging';
    });
});

it('catches exceptions and does not re-throw', function () {
    config()->set('watchtower.notifications.webhook_url', 'https://hooks.example.com/notify');
    config()->set('watchtower.log_channel', 'stack');

    Http::fake([
        'hooks.example.com/notify' => fn () => throw new Exception('connection failed'),
    ]);

    // Should not throw — exceptions are caught and logged
    expect(fn () => $this->listener->handle($this->event))->not->toThrow(Exception::class);
});
