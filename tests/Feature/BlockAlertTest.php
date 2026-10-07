<?php

declare(strict_types=1);

use GuzzleHttp\Client;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Middleware;
use GuzzleHttp\Psr7\Response;
use Illuminate\Cache\ArrayStore;
use Illuminate\Console\Scheduling\Schedule;
use Illuminate\Notifications\AnonymousNotifiable;
use Illuminate\Notifications\ChannelManager;
use Illuminate\Notifications\SlackChannelServiceProvider;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Notification;
use Watchtower\Enums\BlockSource;
use Watchtower\Events\WouldHaveBlocked;
use Watchtower\Notifications\BlockAlert;
use Watchtower\Services\BlacklistService;
use Watchtower\Support\BlockScope;
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
        'max_per_window'     => 20,
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

    event(new WouldHaveBlocked('198.51.100.1', 'test', 'warn mode', BlockScope::GLOBAL));
    block('198.51.100.1', BlockSource::Auto);

    Notification::assertSentOnDemandTimes(BlockAlert::class, 2);
});

it('keeps the block when the send fails, logs it, and gives the address its slot back', function () {
    config()->set('watchtower.notifications.alerts.notification', WatchtowerTestFlakyAlert::class);
    WatchtowerTestFlakyAlert::$failures = 1;
    Log::shouldReceive('channel')->andReturnSelf();
    Log::shouldReceive('warning')->once()->withArgs(fn (string $msg, array $ctx) => $msg === 'Watchtower: block alert failed'
        && $ctx['ip'] === '198.51.100.1'
        && $ctx['error'] === 'mailer down');

    block('198.51.100.1', BlockSource::Auto);
    $this->assertDatabaseHas('blacklisted_ips', ['ip' => '198.51.100.1']);
    Notification::assertNothingSent();

    // The failed send must not have used up the window: the next block of
    // the same address is still reported.
    app(BlacklistService::class)->unblock('198.51.100.1');
    block('198.51.100.1', BlockSource::Auto);

    Notification::assertSentOnDemandTimes(WatchtowerTestFlakyAlert::class, 1);
});

it('logs and moves on when the throttle cache itself throws', function () {
    Cache::extend('watchtower-broken', fn () => Cache::repository(new class extends ArrayStore
    {
        public function put($key, $value, $seconds)
        {
            throw new RuntimeException('cache down');
        }
    }));
    config()->set('cache.stores.watchtower-broken', ['driver' => 'watchtower-broken']);
    config()->set('watchtower.cache.store', 'watchtower-broken');
    config()->set('watchtower.notifications.alerts.would_have_blocked', true);
    Log::shouldReceive('channel')->andReturnSelf();
    Log::shouldReceive('warning')->once()->withArgs(fn (string $msg, array $ctx) => $msg === 'Watchtower: block alert failed'
        && $ctx['error'] === 'cache down');

    // The near-miss path runs inside the request a detector is checking.
    event(new WouldHaveBlocked('198.51.100.1', 'test', 'warn mode', BlockScope::GLOBAL));

    Notification::assertNothingSent();
});

it('hands the address back when the cache fails after claiming it', function () {
    WatchtowerTestFlakyCounterStore::$failures = 1;
    Cache::extend('watchtower-flaky-counter', fn () => Cache::repository(new WatchtowerTestFlakyCounterStore));
    config()->set('cache.stores.watchtower-flaky-counter', ['driver' => 'watchtower-flaky-counter']);
    config()->set('watchtower.cache.store', 'watchtower-flaky-counter');
    config()->set('watchtower.notifications.alerts.would_have_blocked', true);

    // The address's slot is taken, then counting toward the cap throws.
    event(new WouldHaveBlocked('198.51.100.1', 'test', 'warn mode', BlockScope::GLOBAL));
    Notification::assertNothingSent();

    event(new WouldHaveBlocked('198.51.100.1', 'test', 'warn mode', BlockScope::GLOBAL));
    Notification::assertSentOnDemandTimes(BlockAlert::class, 1);
});

it('keeps sending on the other channels when one throws, and keeps the slot once one delivered', function () {
    config()->set('watchtower.notifications.alerts.routes', ['slack' => 'https://hooks.slack.com/x', 'mail' => 'ops@example.com']);
    config()->set('watchtower.notifications.alerts.notification', WatchtowerTestBrokenSlackAlert::class);

    block('198.51.100.1', BlockSource::Auto);
    app(BlacklistService::class)->unblock('198.51.100.1');
    block('198.51.100.1', BlockSource::Auto);

    // Slack, first in line, throws every time. The mail behind it still goes
    // out, once: having delivered, the alert keeps its slot.
    Notification::assertSentOnDemandTimes(WatchtowerTestBrokenSlackAlert::class, 1);
    Notification::assertSentOnDemand(WatchtowerTestBrokenSlackAlert::class, fn ($a, array $via) => $via === ['mail']);
});

it('does not count a failed send toward the cap', function () {
    config()->set('watchtower.notifications.alerts.max_per_window', 1);
    config()->set('watchtower.notifications.alerts.notification', WatchtowerTestFlakyAlert::class);
    WatchtowerTestFlakyAlert::$failures = 1;

    block('198.51.100.1', BlockSource::Auto);
    block('198.51.100.2', BlockSource::Auto);

    Notification::assertSentOnDemand(WatchtowerTestFlakyAlert::class, fn ($a) => $a->alert['ip'] === '198.51.100.2');
});

it('lets an address the cap held back alert once the window turns over', function () {
    config()->set('watchtower.notifications.alerts.max_per_window', 1);
    $this->travelTo(now()->startOfHour()->addMinutes(59));

    block('198.51.100.1', BlockSource::Auto);
    block('198.51.100.2', BlockSource::Auto);
    Notification::assertSentOnDemandTimes(BlockAlert::class, 1);

    // The cap's window has turned over; .2 never got an alert, so nothing
    // of its own should still be holding it back.
    $this->travel(2)->minutes();
    app(BlacklistService::class)->unblock('198.51.100.2');
    block('198.51.100.2', BlockSource::Auto);

    Notification::assertSentOnDemandTimes(BlockAlert::class, 2);
});

it('recovers at the next window when the cap counter lost its TTL', function () {
    // The counter's add() is lost (the key expired or was evicted before
    // increment()), so increment() recreates it with no TTL — on the array
    // store and Redis alike. Named by window, it can only mute its own.
    Cache::extend('watchtower-lossy-counter', fn () => Cache::repository(new WatchtowerTestLossyCounterStore));
    config()->set('cache.stores.watchtower-lossy-counter', ['driver' => 'watchtower-lossy-counter']);
    config()->set('watchtower.cache.store', 'watchtower-lossy-counter');
    config()->set('watchtower.notifications.alerts.max_per_window', 1);
    $this->travelTo(now()->startOfHour());

    block('198.51.100.1', BlockSource::Auto);
    block('198.51.100.2', BlockSource::Auto);
    Notification::assertSentOnDemandTimes(BlockAlert::class, 1);

    $this->travel(61)->minutes();
    block('198.51.100.3', BlockSource::Auto);

    Notification::assertSentOnDemandTimes(BlockAlert::class, 2);
});

it('sends the alert without a link when APP_URL is empty', function () {
    config()->set('app.url', '');

    block('198.51.100.1', BlockSource::Auto);

    Notification::assertSentOnDemand(BlockAlert::class, fn (BlockAlert $a) => $a->alert['url'] === null);
});

it('caps alerts per window across addresses, and logs reaching the cap once', function () {
    config()->set('watchtower.notifications.alerts.max_per_window', 2);
    $channel = Mockery::mock()->shouldIgnoreMissing();
    $channel->shouldReceive('warning')->once()->withArgs(fn (string $msg, array $ctx) => $msg === 'Watchtower: alert cap reached, further alerts suppressed'
        && $ctx['type'] === 'blocked' && $ctx['max_per_window'] === 2);
    Log::shouldReceive('channel')->andReturn($channel);

    foreach (['198.51.100.1', '198.51.100.2', '198.51.100.3', '198.51.100.4'] as $ip) {
        block($ip, BlockSource::Auto);
    }

    Notification::assertSentOnDemandTimes(BlockAlert::class, 2);

    // Its own count: near misses are not crowded out by the blocks.
    config()->set('watchtower.notifications.alerts.would_have_blocked', true);
    event(new WouldHaveBlocked('198.51.100.5', 'test', 'warn mode', BlockScope::GLOBAL));

    Notification::assertSentOnDemandTimes(BlockAlert::class, 3);
});

it('sends every alert when throttle_minutes is 0', function () {
    config()->set('watchtower.notifications.alerts.throttle_minutes', 0);
    config()->set('watchtower.notifications.alerts.max_per_window', 1);

    block('198.51.100.1', BlockSource::Auto);
    app(BlacklistService::class)->unblock('198.51.100.1');
    block('198.51.100.1', BlockSource::Auto);
    block('198.51.100.2', BlockSource::Auto);

    Notification::assertSentOnDemandTimes(BlockAlert::class, 3);
});

it('throttles a near miss by its /64 and scope, and keeps the rule config out of the queued payload', function () {
    config()->set('watchtower.notifications.alerts.would_have_blocked', true);
    $context = ['rule_index' => 0, 'rule' => ['message_contains' => 'x'], 'threshold' => 3];

    event(new WouldHaveBlocked('2001:db8::1', 'test', 'warn mode', 'auth', $context));
    event(new WouldHaveBlocked('2001:db8::2', 'test', 'warn mode', 'auth', $context));
    event(new WouldHaveBlocked('2001:db8::3', 'test', 'warn mode', BlockScope::GLOBAL, $context));

    Notification::assertSentOnDemandTimes(BlockAlert::class, 2);
    Notification::assertSentOnDemand(BlockAlert::class, function (BlockAlert $alert) {
        return $alert->alert['scope'] === 'auth'
            && ! array_key_exists('rule', $alert->alert['context'])
            && $alert->alert['context']['rule_index'] === 0
            && unserialize(serialize($alert))->alert === $alert->alert;
    });
});

it('alerts on a never_auto_block near miss in block mode', function () {
    config()->set('watchtower.never_auto_block', ['203.0.113.12']);
    config()->set('watchtower.notifications.alerts.would_have_blocked', true);

    probe('203.0.113.12');

    $this->assertDatabaseMissing('blacklisted_ips', ['ip' => '203.0.113.12']);
    Notification::assertSentOnDemand(BlockAlert::class, fn (BlockAlert $a) => $a->alert['not_blocked_because'] === 'never_auto_block');
});

it('routes to whichever channels have a value, one send per channel', function (array $routes, array $expected) {
    config()->set('watchtower.notifications.alerts.routes', $routes);

    block('198.51.100.1', BlockSource::Auto);

    Notification::assertSentOnDemandTimes(BlockAlert::class, count($expected));

    foreach ($expected as $channel => $route) {
        Notification::assertSentOnDemand(BlockAlert::class, fn (BlockAlert $a, array $via, AnonymousNotifiable $to) => $via === [$channel]
            && $to->routes === [$channel => $route]);
    }
})->with([
    'slack only'     => [['mail' => null, 'slack' => 'https://hooks.slack.com/x'], ['slack' => 'https://hooks.slack.com/x']],
    'mail as a list' => [['mail' => ['a@example.com'], 'slack' => []], ['mail' => ['a@example.com']]],
    'both'           => [['mail' => 'a@example.com', 'slack' => 'https://hooks.slack.com/x'], ['mail' => ['a@example.com'], 'slack' => 'https://hooks.slack.com/x']],
]);

it('sends the configured notification class on the notifications queue', function () {
    config()->set('watchtower.notifications.queue', 'alerts');
    config()->set('watchtower.notifications.alerts.notification', WatchtowerTestFlakyAlert::class);
    WatchtowerTestFlakyAlert::$failures = 0;

    block('198.51.100.1', BlockSource::Auto);

    Notification::assertSentOnDemand(WatchtowerTestFlakyAlert::class, fn ($alert) => $alert->queue === 'alerts');
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

it('renders a rule near miss, a permanent block, and no link when the UI is off', function () {
    $nearMiss = new BlockAlert([
        'type'                => 'would_have_blocked',
        'ip'                  => '198.51.100.1',
        'reason'              => 'Log rule',
        'scope'               => null,
        'not_blocked_because' => 'warn mode',
        'context'             => ['rule_index' => 2, 'in_block_mode' => 'shared IP'],
        'url'                 => 'https://app.test/watchtower',
    ]);
    $permanent = (new BlockAlert([
        'type'       => 'blocked',
        'ip'         => '198.51.100.2',
        'reason'     => 'by hand',
        'scope'      => null,
        'source'     => 'manual',
        'expires_at' => null,
        'url'        => null,
    ]))->toMail(new AnonymousNotifiable);

    expect($nearMiss->lines())->toContain('Rule: auto_block.rules[2]', 'In block mode: shared IP', 'Not blocked because: warn mode')
        ->and($nearMiss->toSlack(new AnonymousNotifiable)->toArray()['text'])->toContain('<https://app.test/watchtower|Open Watchtower>')
        ->and($permanent->introLines)->toContain('Expires: never', 'Source: manual')
        ->and($permanent->actionUrl)->toBeNull();
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

it('builds the alert link from APP_URL, not the Host header of the request that tripped the detector', function () {
    config()->set('app.url', 'https://app.test');

    $this->withServerVariables(['REMOTE_ADDR' => '203.0.113.8'])->get('http://evil.test/.env');

    Notification::assertSentOnDemand(BlockAlert::class, fn (BlockAlert $a) => $a->alert['url'] === 'https://app.test'.route('watchtower.ui.index', [], false));
});

it('does not schedule the digest while it is off', function () {
    expect(collect(app(Schedule::class)->events())
        ->contains(fn ($event) => $event->description === 'watchtower:alert-digest'))->toBeFalse();
});

class WatchtowerTestFlakyAlert extends BlockAlert
{
    public static int $failures = 0;

    public function via(object $notifiable): array
    {
        if (self::$failures > 0) {
            self::$failures--;

            throw new RuntimeException('mailer down');
        }

        return parent::via($notifiable);
    }
}

class WatchtowerTestFlakyCounterStore extends ArrayStore
{
    public static int $failures = 0;

    public function increment($key, $value = 1)
    {
        if (self::$failures > 0) {
            self::$failures--;

            throw new RuntimeException('cache blip');
        }

        return parent::increment($key, $value);
    }
}

class WatchtowerTestBrokenSlackAlert extends BlockAlert
{
    public function via(object $notifiable): array
    {
        if (array_key_exists('slack', $notifiable->routes)) {
            throw new RuntimeException('slack webhook 404');
        }

        return parent::via($notifiable);
    }
}

class WatchtowerTestLossyCounterStore extends ArrayStore
{
    public function put($key, $value, $seconds)
    {
        // Only the write with a TTL — add()'s. increment() on a missing key
        // stores it forever (seconds 0), and that write has to land.
        return str_contains($key, ':alert:') && str_contains($key, ':count') && $seconds > 0
            ? true
            : parent::put($key, $value, $seconds);
    }
}
