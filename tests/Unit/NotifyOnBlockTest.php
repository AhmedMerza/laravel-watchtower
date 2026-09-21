<?php

declare(strict_types=1);

use Illuminate\Events\CallQueuedListener;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Queue;
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

it('sends null for the scope of an app-wide block, not the empty string the column stores', function () {
    config()->set('watchtower.notifications.webhook_url', 'https://hooks.example.com/notify');
    Http::fake(['hooks.example.com/notify' => Http::response([], 200)]);

    $this->listener->handle($this->event);

    Http::assertSent(fn ($request) => array_key_exists('scope', $request->data())
        && $request->data()['scope'] === null);
});

it('sends the scope name for a scoped block', function () {
    config()->set('watchtower.scopes', ['auth']);
    config()->set('watchtower.notifications.webhook_url', 'https://hooks.example.com/notify');
    Http::fake(['hooks.example.com/notify' => Http::response([], 200)]);

    $scoped = BlacklistedIp::create([
        'ip'         => '5.6.7.8',
        'scope'      => 'auth',
        'reason'     => 'test',
        'source'     => BlockSource::Manual,
        'source_env' => 'staging',
    ]);

    $this->listener->handle(new IpBlocked($scoped));

    Http::assertSent(fn ($request) => $request->data()['scope'] === 'auth');
});

it('queues the webhook on the configured notification queue', function () {
    config()->set('watchtower.notifications.queue', 'notifications');

    Queue::fake();

    event($this->event);

    Queue::assertPushedOn('notifications', CallQueuedListener::class,
        fn ($job) => $job->class === NotifyOnBlock::class);
});

it('queues the webhook on default when no notification queue is named', function () {
    config()->set('watchtower.notifications.queue', 'default');

    Queue::fake();

    event($this->event);

    Queue::assertPushedOn('default', CallQueuedListener::class,
        fn ($job) => $job->class === NotifyOnBlock::class);
});
