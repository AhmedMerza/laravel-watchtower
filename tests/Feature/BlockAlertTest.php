<?php

declare(strict_types=1);

use GuzzleHttp\Client;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Middleware;
use GuzzleHttp\Psr7\Response;
use Illuminate\Notifications\AnonymousNotifiable;
use Illuminate\Notifications\ChannelManager;
use Illuminate\Notifications\SlackChannelServiceProvider;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Notification;
use Watchtower\Enums\BlockSource;
use Watchtower\Events\WouldHaveBlocked;
use Watchtower\Notifications\BlockAlert;
use Watchtower\Services\BlacklistService;
use Watchtower\Tests\TestCase;

// Real traffic through a real detector, so the alert is proven against the
// block path and the near-miss path that produce it — not a hand-fired event.
beforeAll(function () {
    TestCase::$beforeBoot = function ($app) {
        $app['config']->set('cache.default', 'array');
        $app['config']->set('watchtower.cache.store', 'array');
        $app['config']->set('watchtower.auto_block.enabled', true);
        $app['config']->set('watchtower.auto_block.mode', 'block');
        $app['config']->set('watchtower.auto_block.detectors.scanner_paths.enabled', true);
    };
});

afterAll(function () {
    TestCase::$beforeBoot = null;
});

beforeEach(function () {
    config()->set('watchtower.notifications.alerts', [
        'enabled'            => true,
        'routes'             => ['mail' => 'ops@example.com, oncall@example.com', 'slack' => null],
        'throttle_minutes'   => 60,
        'manual'             => false,
        'would_have_blocked' => false,
        'notification'       => BlockAlert::class,
    ]);

    Notification::fake();
});

function probe(string $ip): void
{
    test()->withServerVariables(['REMOTE_ADDR' => $ip])->get('/.env');
}

function block(string $ip, BlockSource $source): void
{
    app(BlacklistService::class)->block($ip, ['reason' => 'test', 'source' => $source]);
}

it('alerts on an auto-block, to every recipient on the mail route', function () {
    probe('203.0.113.8');

    Notification::assertSentOnDemand(BlockAlert::class, function (BlockAlert $alert, array $channels, AnonymousNotifiable $to) {
        return $channels === ['mail']
            && $to->routes['mail'] === ['ops@example.com', 'oncall@example.com']
            && $alert->alert['type'] === 'blocked'
            && $alert->alert['ip'] === '203.0.113.8'
            && $alert->alert['source'] === 'auto'
            && $alert->alert['expires_at'] !== null;
    });
});

it('sends nothing while alerts are off, or with no route set', function (array $override) {
    config()->set('watchtower.notifications.alerts', [...config('watchtower.notifications.alerts'), ...$override]);

    probe('203.0.113.8');

    $this->assertDatabaseHas('blacklisted_ips', ['ip' => '203.0.113.8']);
    Notification::assertNothingSent();
})->with([
    'off'      => [['enabled' => false]],
    'no route' => [['routes' => ['mail' => '', 'slack' => null]]],
]);

it('sends at most one alert per address in the throttle window', function () {
    block('198.51.100.1', BlockSource::Auto);
    app(BlacklistService::class)->unblock('198.51.100.1');
    block('198.51.100.1', BlockSource::Auto);
    block('198.51.100.2', BlockSource::Auto);

    Notification::assertSentOnDemandTimes(BlockAlert::class, 2);

    $this->travel(61)->minutes();
    app(BlacklistService::class)->unblock('198.51.100.1');
    block('198.51.100.1', BlockSource::Auto);

    Notification::assertSentOnDemandTimes(BlockAlert::class, 3);
});

it('alerts on manual blocks only when asked, and never on sync or feed blocks', function () {
    block('198.51.100.1', BlockSource::Manual);
    block('198.51.100.2', BlockSource::Sync);
    block('198.51.100.3', BlockSource::Feed);

    Notification::assertNothingSent();

    config()->set('watchtower.notifications.alerts.manual', true);
    block('198.51.100.4', BlockSource::Manual);
    block('198.51.100.5', BlockSource::Sync);
    block('198.51.100.6', BlockSource::Feed);

    Notification::assertSentOnDemandTimes(BlockAlert::class, 1);
    Notification::assertSentOnDemand(BlockAlert::class, fn (BlockAlert $a) => $a->alert['ip'] === '198.51.100.4');
});

it('alerts on a warn-mode near miss only when asked, saying why nothing was blocked', function () {
    config()->set('watchtower.auto_block.mode', 'warn');

    probe('203.0.113.9');
    Notification::assertNothingSent();

    config()->set('watchtower.notifications.alerts.would_have_blocked', true);
    probe('203.0.113.10');

    $this->assertDatabaseMissing('blacklisted_ips', ['ip' => '203.0.113.10']);
    Notification::assertSentOnDemand(BlockAlert::class, function (BlockAlert $alert) {
        return $alert->alert['type'] === 'would_have_blocked'
            && $alert->alert['ip'] === '203.0.113.10'
            && $alert->alert['not_blocked_because'] === 'warn mode'
            && $alert->alert['context']['detector'] === 'scanner_paths'
            && array_key_exists('in_block_mode', $alert->alert['context']);
    });
});

it('throttles a near miss and a block separately, so the block still alerts', function () {
    config()->set('watchtower.notifications.alerts.would_have_blocked', true);

    event(new WouldHaveBlocked('198.51.100.1', 'test', 'warn mode', ''));
    block('198.51.100.1', BlockSource::Auto);

    Notification::assertSentOnDemandTimes(BlockAlert::class, 2);
});

it('keeps the block when the alert throws, and logs why it did not send', function () {
    config()->set('watchtower.notifications.alerts.notification', 'NoSuchAlertClass');
    Log::shouldReceive('channel')->andReturnSelf();
    Log::shouldReceive('warning')->once()->withArgs(fn (string $msg, array $ctx) => $msg === 'Watchtower: block alert failed'
        && $ctx['ip'] === '198.51.100.1');

    block('198.51.100.1', BlockSource::Auto);

    $this->assertDatabaseHas('blacklisted_ips', ['ip' => '198.51.100.1']);
});

it('renders a block alert as mail', function () {
    $mail = (new BlockAlert([
        'type'       => 'blocked',
        'ip'         => '198.51.100.1',
        'reason'     => 'Scanner probe',
        'scope'      => 'auth',
        'source'     => 'auto',
        'expires_at' => '2026-10-07T12:00:00+00:00',
        'context'    => [],
        'url'        => 'https://app.test/watchtower',
    ]))->toMail(new AnonymousNotifiable);

    expect($mail->subject)->toBe('Watchtower blocked 198.51.100.1')
        ->and($mail->introLines)->toContain('Address: 198.51.100.1', 'Scope: auth', 'Expires: 2026-10-07T12:00:00+00:00')
        ->and($mail->actionUrl)->toBe('https://app.test/watchtower');
});

it('posts a Slack alert to the incoming-webhook URL through the official channel', function () {
    // The package's webhook channel posts with its own Guzzle client, not the
    // Http facade, so the request is caught at Guzzle's handler stack.
    $sent = [];
    $stack = HandlerStack::create(new MockHandler([new Response(200)]));
    $stack->push(Middleware::history($sent));
    $this->app->instance(Client::class, new Client(['handler' => $stack]));
    // beforeEach faked the manager; this test needs the real one, with the
    // package's 'slack' driver registered on it.
    Notification::swap(new ChannelManager($this->app));
    $this->app->register(SlackChannelServiceProvider::class);

    Notification::route('slack', 'https://hooks.slack.com/services/T/B/X')->notifyNow(new BlockAlert([
        'type'                => 'would_have_blocked',
        'ip'                  => '198.51.100.1',
        'reason'              => 'Scanner probe',
        'scope'               => null,
        'not_blocked_because' => 'warn mode',
        'context'             => ['detector' => 'scanner_paths', 'in_block_mode' => null],
        'url'                 => null,
    ]));

    expect($sent)->toHaveCount(1);
    $request = $sent[0]['request'];
    $text = json_decode((string) $request->getBody(), true)['text'];

    expect((string) $request->getUri())->toBe('https://hooks.slack.com/services/T/B/X')
        ->and($text)->toContain('Watchtower would have blocked 198.51.100.1', 'Detector: scanner_paths', 'Scope: whole app', 'In block mode: it would have been blocked');
});
