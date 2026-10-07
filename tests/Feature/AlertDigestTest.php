<?php

declare(strict_types=1);

use Illuminate\Console\Scheduling\Schedule;
use Illuminate\Notifications\AnonymousNotifiable;
use Illuminate\Notifications\Messages\MailMessage;
use Illuminate\Notifications\Notification as BaseNotification;
use Illuminate\Notifications\Slack\SlackMessage;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Facade;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Notification;
use Illuminate\Support\Facades\Schema;
use Symfony\Component\Mime\Email;
use Watchtower\Console\Commands\AlertDigestCommand;
use Watchtower\Console\Commands\CleanupCommand;
use Watchtower\Enums\BlockSource;
use Watchtower\Events\WouldHaveBlocked;
use Watchtower\Notifications\BlockAlert;
use Watchtower\Notifications\BlockDigest;
use Watchtower\Services\BlacklistService;
use Watchtower\Support\BlockScope;
use Watchtower\Tests\TestCase;
use Watchtower\WatchtowerServiceProvider;

beforeAll(function () {
    TestCase::$beforeBoot = function ($app) {
        $app['config']->set('cache.default', 'array');
        $app['config']->set('watchtower.cache.store', 'array');
        $app['config']->set('watchtower.auto_block.enabled', true);
        $app['config']->set('watchtower.auto_block.mode', 'warn');
        $app['config']->set('watchtower.auto_block.detectors.scanner_paths.enabled', true);
        $app['config']->set('watchtower.notifications.alerts.enabled', true);
        $app['config']->set('watchtower.notifications.alerts.digest.enabled', true);
        $app['config']->set('watchtower.notifications.alerts.digest.at', '07:30');
    };
});

afterAll(function () {
    TestCase::$beforeBoot = null;
});

beforeEach(function () {
    config()->set('mail.default', 'array');
    config()->set('app.url', 'https://app.test');
    config()->set('watchtower.notifications.alerts', [
        'enabled'            => true,
        'routes'             => ['mail' => 'ops@example.com', 'slack' => null],
        'throttle_minutes'   => 60,
        'max_per_window'     => 20,
        'manual'             => false,
        'would_have_blocked' => true,
        'notification'       => BlockAlert::class,
        'digest'             => [
            'enabled'      => true,
            'at'           => '07:30',
            'instant'      => true,
            'notification' => BlockDigest::class,
        ],
    ]);
});

function digestBlock(string $ip, ?string $scope = null): void
{
    app(BlacklistService::class)->block($ip, ['reason' => 'Scanner probe', 'source' => BlockSource::Auto, 'scope' => $scope]);
}

function digestReblock(string $ip): void
{
    app(BlacklistService::class)->unblock($ip);
    digestBlock($ip);
}

function digestNearMiss(string $ip): void
{
    test()->withServerVariables(['REMOTE_ADDR' => $ip])->get('/.env');
}

/**
 * @param  array<string, mixed>  $overrides
 */
function digestRow(array $overrides = []): void
{
    DB::table('watchtower_alert_digest')->insert([
        'type'      => 'blocked',
        'ip'        => '198.51.100.1',
        'scope'     => '',
        'reason'    => 'Scanner probe',
        'events'    => 1,
        'held_back' => 0,
        'sealed'    => false,
        'first_at'  => now(),
        'last_at'   => now(),
        ...$overrides,
    ]);
}

/**
 * @return list<Email>
 */
function sentMail(): array
{
    return app('mailer')->getSymfonyTransport()->messages()
        ->map(fn ($message) => $message->getOriginalMessage())
        ->all();
}

it('counts an address\'s repeats into one row, with what the throttle held back', function () {
    Notification::fake();

    digestBlock('198.51.100.1');
    digestReblock('198.51.100.1');
    digestReblock('198.51.100.1');

    Notification::assertSentOnDemandTimes(BlockAlert::class, 1);
    $row = DB::table('watchtower_alert_digest')->sole();
    expect((int) $row->events)->toBe(3)
        ->and((int) $row->held_back)->toBe(2);
});

it('records what the cap held back', function () {
    Notification::fake();
    config()->set('watchtower.notifications.alerts.max_per_window', 1);

    digestBlock('198.51.100.1');
    digestBlock('198.51.100.2');

    expect(DB::table('watchtower_alert_digest')->orderBy('ip')->pluck('held_back', 'ip')->map(fn ($n) => (int) $n)->all())
        ->toBe(['198.51.100.1' => 0, '198.51.100.2' => 1]);
});

it('records an instant alert that went out on no channel as held back', function () {
    config()->set('watchtower.notifications.alerts.notification', WatchtowerTestBrokenInstantAlert::class);

    digestBlock('198.51.100.1');

    expect((int) DB::table('watchtower_alert_digest')->sole()->held_back)->toBe(1);
});

it('starts a new row when the digest seals the open one between finding and counting it', function () {
    Notification::fake();
    digestBlock('198.51.100.1');

    // The digest's seal landing in the gap between the listener's lookup
    // and its update.
    $sealed = false;
    DB::listen(function ($query) use (&$sealed) {
        if (! $sealed && str_starts_with($query->sql, 'select') && str_contains($query->sql, 'watchtower_alert_digest')) {
            $sealed = true;
            DB::table('watchtower_alert_digest')->update(['sealed' => true]);
        }
    });

    digestReblock('198.51.100.1');

    expect(DB::table('watchtower_alert_digest')->orderBy('id')->get(['events', 'sealed'])->map(fn ($r) => [(int) $r->events, (bool) $r->sealed])->all())
        ->toBe([[1, true], [1, false]]);
});

it('keeps a row per kind, reason and why-not for one address', function () {
    Notification::fake();
    $nearMiss = fn (string $reason, string $why) => event(new WouldHaveBlocked('198.51.100.1', $reason, $why, BlockScope::GLOBAL));

    digestRow(['reason' => 'scanner']);
    $nearMiss('scanner', 'warn mode');
    $nearMiss('scanner', 'warn mode');
    $nearMiss('scanner', 'shared IP');
    $nearMiss('bursts', 'warn mode');

    expect(DB::table('watchtower_alert_digest')->orderBy('id')->get()->map(fn ($r) => [$r->type, $r->reason, $r->not_blocked_because, (int) $r->events])->all())
        ->toBe([
            ['blocked', 'scanner', null, 1],
            ['would_have_blocked', 'scanner', 'warn mode', 2],
            ['would_have_blocked', 'scanner', 'shared IP', 1],
            ['would_have_blocked', 'bursts', 'warn mode', 1],
        ]);
});

it('records a near miss under its /64, saying why it was not blocked', function () {
    Notification::fake();

    digestNearMiss('2001:db8:1:2::9');

    $row = DB::table('watchtower_alert_digest')->sole();
    expect($row->type)->toBe('would_have_blocked')
        ->and($row->ip)->toBe('2001:db8:1:2::/64')
        ->and($row->not_blocked_because)->toBe('warn mode');
});

it('sends only the digest when instant is off', function () {
    Notification::fake();
    config()->set('watchtower.notifications.alerts.digest.instant', false);

    digestBlock('198.51.100.1');

    Notification::assertNothingSent();
    expect((int) DB::table('watchtower_alert_digest')->sole()->events)->toBe(1);
});

it('records nothing with the digest off, or with no route to send it on', function (array $override) {
    Notification::fake();
    config()->set('watchtower.notifications.alerts', array_replace_recursive(config('watchtower.notifications.alerts'), $override));

    digestBlock('198.51.100.1');

    expect(DB::table('watchtower_alert_digest')->count())->toBe(0);
})->with([
    'digest off' => [['digest' => ['enabled' => false]]],
    'no route'   => [['routes' => ['mail' => null]]],
]);

it('keeps the block when the digest table is missing', function () {
    Notification::fake();
    Schema::drop('watchtower_alert_digest');
    Log::shouldReceive('channel')->andReturnSelf();
    Log::shouldReceive('warning')->once()->withArgs(fn (string $msg) => $msg === 'Watchtower: could not record the alert for the digest');

    digestBlock('198.51.100.1');

    $this->assertDatabaseHas('blacklisted_ips', ['ip' => '198.51.100.1']);
    Notification::assertSentOnDemandTimes(BlockAlert::class, 1);
});

it('mails one digest, blocks first and busiest first, then deletes what it sent', function () {
    // The busier block on the higher address, and the near miss on a lower
    // address than both: neither the grouping nor insertion order gives
    // this order by accident.
    digestBlock('198.51.100.5');
    digestBlock('198.51.100.9');
    digestReblock('198.51.100.9');
    digestReblock('198.51.100.9');
    digestNearMiss('198.51.100.1');

    expect(sentMail())->toHaveCount(3);
    app('mailer')->getSymfonyTransport()->flush();

    $this->artisan('watchtower:alert-digest')->assertSuccessful();

    $mail = sentMail();
    expect($mail)->toHaveCount(1);

    $body = $mail[0]->getTextBody();
    expect($mail[0]->getSubject())->toBe('Watchtower digest: 2 blocked, 1 would have been')
        ->and($mail[0]->getTo()[0]->getAddress())->toBe('ops@example.com')
        ->and($body)->toContain('Blocked 198.51.100.9 (3 times) — Scanner probe — scope: whole app')
        ->and($body)->toContain('2 not alerted at the time (throttle or cap)')
        ->and($body)->toContain('Would have blocked 198.51.100.1')
        ->and($body)->toContain('not blocked because: warn mode')
        ->and($body)->toContain('https://app.test'.route('watchtower.ui.index', [], false))
        ->and(strpos($body, '198.51.100.9'))->toBeLessThan(strpos($body, '198.51.100.5'))
        ->and(strpos($body, '198.51.100.5'))->toBeLessThan(strpos($body, 'Would have blocked 198.51.100.1'));

    expect(DB::table('watchtower_alert_digest')->count())->toBe(0);
});

it('lists the same address in two scopes as two entries', function () {
    Notification::fake();
    config()->set('watchtower.notifications.alerts.digest.instant', false);

    digestBlock('198.51.100.1');
    digestBlock('198.51.100.1', 'auth');

    $this->artisan('watchtower:alert-digest')->assertSuccessful();

    Notification::assertSentOnDemand(BlockDigest::class, function (BlockDigest $digest) {
        $lines = collect($digest->lines());

        return $digest->digest['totals']['blocked'] === 2
            && count($digest->digest['entries']) === 2
            && $lines->contains(fn ($l) => str_contains($l, 'scope: auth'))
            && $lines->contains(fn ($l) => str_contains($l, 'scope: whole app'));
    });
});

it('sends nothing when there is nothing to report', function () {
    Notification::fake();

    $this->artisan('watchtower:alert-digest')->assertSuccessful();

    Notification::assertNothingSent();
});

it('sends nothing and keeps the rows while alerts, the digest or every route is off', function (array $override) {
    Notification::fake();
    digestRow();
    config()->set('watchtower.notifications.alerts', array_replace_recursive(config('watchtower.notifications.alerts'), $override));

    $this->artisan('watchtower:alert-digest')->assertSuccessful();

    Notification::assertNothingSent();
    expect(DB::table('watchtower_alert_digest')->count())->toBe(1);
})->with([
    'alerts off' => [['enabled' => false]],
    'digest off' => [['digest' => ['enabled' => false]]],
    'no route'   => [['routes' => ['mail' => null]]],
]);

it('fails with a hint when the migration has not been run', function () {
    Schema::drop('watchtower_alert_digest');

    $this->artisan('watchtower:alert-digest')
        ->expectsOutputToContain('watchtower_alert_digest table is missing')
        ->assertFailed();
});

it('keeps the rows when the digest goes out on no channel, and sends them with the next one', function () {
    config()->set('watchtower.notifications.alerts.digest.instant', false);
    config()->set('watchtower.notifications.alerts.digest.notification', WatchtowerTestBrokenDigest::class);
    digestBlock('198.51.100.1');

    $this->artisan('watchtower:alert-digest')->assertFailed();

    expect(sentMail())->toBe([])
        ->and(DB::table('watchtower_alert_digest')->count())->toBe(1);

    digestBlock('198.51.100.2');
    config()->set('watchtower.notifications.alerts.digest.notification', BlockDigest::class);

    $this->artisan('watchtower:alert-digest')->assertSuccessful();

    expect(sentMail()[0]->getTextBody())->toContain('198.51.100.1', '198.51.100.2')
        ->and(DB::table('watchtower_alert_digest')->count())->toBe(0);
});

it('deletes the rows once any channel delivered, after trying every channel', function () {
    WatchtowerTestRecordingChannel::$sent = 0;
    Notification::extend('recording', fn () => new WatchtowerTestRecordingChannel);
    config()->set('watchtower.notifications.alerts.digest.instant', false);
    config()->set('watchtower.notifications.alerts.routes', ['mail' => 'ops@example.com', 'recording' => 'x']);
    config()->set('watchtower.notifications.alerts.digest.notification', WatchtowerTestBrokenDigest::class);
    digestBlock('198.51.100.1');

    $this->artisan('watchtower:alert-digest')->assertSuccessful();

    expect(WatchtowerTestRecordingChannel::$sent)->toBe(1)
        ->and(DB::table('watchtower_alert_digest')->count())->toBe(0);
});

it('sends on every channel, not just the first that delivers', function () {
    WatchtowerTestRecordingChannel::$sent = 0;
    Notification::extend('recording', fn () => new WatchtowerTestRecordingChannel);
    config()->set('watchtower.notifications.alerts.digest.instant', false);
    config()->set('watchtower.notifications.alerts.routes', ['recording' => 'x', 'mail' => 'ops@example.com']);
    digestBlock('198.51.100.1');

    $this->artisan('watchtower:alert-digest')->assertSuccessful();

    expect(WatchtowerTestRecordingChannel::$sent)->toBe(1)
        ->and(sentMail())->toHaveCount(1);
});

it('leaves a repeat that comes in while the digest is sending for the next one', function () {
    config()->set('watchtower.notifications.alerts.digest.instant', false);
    config()->set('watchtower.notifications.alerts.digest.notification', WatchtowerTestBlockDuringSendDigest::class);
    digestBlock('198.51.100.1');

    $this->artisan('watchtower:alert-digest')->assertSuccessful();

    // The same address as the row being sent: counted into that row, it
    // would have been deleted unreported.
    $row = DB::table('watchtower_alert_digest')->sole();
    expect($row->ip)->toBe('198.51.100.1')
        ->and((int) $row->events)->toBe(1);
});

it('lists at most MAX_ENTRIES addresses and counts the rest', function () {
    config()->set('watchtower.notifications.alerts.digest.instant', false);
    Notification::fake();

    foreach (range(1, AlertDigestCommand::MAX_ENTRIES + 3) as $i) {
        digestBlock("198.51.100.{$i}");
    }

    $this->artisan('watchtower:alert-digest')->assertSuccessful();

    Notification::assertSentOnDemand(BlockDigest::class, function (BlockDigest $digest) {
        return count($digest->digest['entries']) === AlertDigestCommand::MAX_ENTRIES
            && $digest->digest['omitted'] === 3
            && $digest->digest['totals']['blocked'] === AlertDigestCommand::MAX_ENTRIES + 3
            && last($digest->lines()) === '…and 3 more not listed here.';
    });
});

it('reports the span from the first event to the last, across every row of an address', function () {
    Notification::fake();

    // One address split over two rows — a race, or a failed run's sealed
    // row beside a fresh one — and a second address in between, so the
    // earliest time and the latest are different rows.
    digestRow(['first_at' => '2026-10-07 09:12:00', 'last_at' => '2026-10-07 10:00:00', 'sealed' => true]);
    digestRow(['first_at' => '2026-10-07 15:00:00', 'last_at' => '2026-10-07 17:40:00']);
    digestRow(['ip' => '198.51.100.2', 'first_at' => '2026-10-07 12:00:00', 'last_at' => '2026-10-07 12:00:00']);

    $this->artisan('watchtower:alert-digest')->assertSuccessful();

    Notification::assertSentOnDemand(BlockDigest::class, fn (BlockDigest $digest) => $digest->digest['since'] === '2026-10-07 09:12:00'
        && str_ends_with($digest->lines()[1], '2026-10-07 09:12 to 2026-10-07 17:40'));
});

it('adds up an address split over several rows', function () {
    Notification::fake();
    digestRow(['events' => 2, 'held_back' => 1, 'sealed' => true]);
    digestRow(['events' => 3, 'held_back' => 2]);

    $this->artisan('watchtower:alert-digest')->assertSuccessful();

    Notification::assertSentOnDemand(BlockDigest::class, fn (BlockDigest $digest) => $digest->digest['entries'][0]['events'] === 5
        && $digest->digest['entries'][0]['held_back'] === 3
        && str_contains($digest->lines()[1], '(5 times)'));
});

it('leaves rows another run sealed while this one was sending', function () {
    config()->set('watchtower.notifications.alerts.digest.instant', false);
    config()->set('watchtower.notifications.alerts.digest.notification', WatchtowerTestOverlappingRunDigest::class);
    digestBlock('198.51.100.1');

    $this->artisan('watchtower:alert-digest')->assertSuccessful();

    expect(DB::table('watchtower_alert_digest')->pluck('ip')->all())->toBe(['198.51.100.2']);
});

it('drops rows no digest took within the retention window on cleanup', function () {
    digestRow(['ip' => '198.51.100.1', 'last_at' => now()->subDays(CleanupCommand::DIGEST_RETENTION_DAYS + 1)]);
    digestRow(['ip' => '198.51.100.2', 'last_at' => now()->subDays(CleanupCommand::DIGEST_RETENTION_DAYS - 1)]);

    $this->artisan('watchtower:cleanup')->assertSuccessful();

    expect(DB::table('watchtower_alert_digest')->pluck('ip')->all())->toBe(['198.51.100.2']);
});

it('cleans up quietly where the digest was never migrated', function () {
    Schema::drop('watchtower_alert_digest');

    $this->artisan('watchtower:cleanup')
        ->doesntExpectOutputToContain('Could not prune the alert digest')
        ->assertSuccessful();
});

function digestFixture(bool $instant, ?string $url): BlockDigest
{
    return new BlockDigest([
        'since'   => '2026-10-07 08:00:00',
        'instant' => $instant,
        'totals'  => ['blocked' => 1, 'would_have_blocked' => 0],
        'entries' => [[
            'type'                => 'blocked',
            'ip'                  => '198.51.100.1',
            'scope'               => 'auth',
            'reason'              => 'Scanner probe',
            'not_blocked_because' => null,
            'events'              => 1,
            'held_back'           => 1,
            'first_at'            => '2026-10-07 09:12:44',
            'last_at'             => '2026-10-07 09:12:59',
        ]],
        'omitted' => 0,
        'url'     => $url,
    ]);
}

it('does not call events held back when instant alerts are off', function () {
    $mail = digestFixture(false, null)->toMail(new AnonymousNotifiable);

    expect($mail->introLines)->toBe([
        'Since 2026-10-07 08:00.',
        'Blocked 198.51.100.1 — Scanner probe — scope: auth — 2026-10-07 09:12',
    ])
        ->and($mail->actionUrl)->toBeNull();
});

it('renders the digest for Slack, with the link when there is one', function () {
    $with = digestFixture(true, 'https://app.test/watchtower')->toSlack(new AnonymousNotifiable)->toArray()['text'];
    $without = digestFixture(true, null)->toSlack(new AnonymousNotifiable)->toArray()['text'];

    expect($with)->toStartWith('*Watchtower digest: 1 blocked, 0 would have been*')
        ->and($with)->toContain('Blocked 198.51.100.1', '1 not alerted at the time')
        ->and($with)->toEndWith('<https://app.test/watchtower|Open Watchtower>')
        ->and($without)->not->toContain('Open Watchtower');
})->skip(fn () => ! class_exists(SlackMessage::class), 'needs laravel/slack-notification-channel');

it('schedules the digest daily at the configured time', function () {
    $event = collect(app(Schedule::class)->events())
        ->first(fn ($event) => $event->description === 'watchtower:alert-digest');

    expect($event)->not->toBeNull()
        ->and($event->expression)->toBe('30 7 * * *');
});

it('does not schedule the digest while alerts are off, even with the digest on', function () {
    config()->set('watchtower.notifications.alerts.enabled', false);
    $this->app->instance(Schedule::class, new Schedule);
    Facade::clearResolvedInstances();

    (new WatchtowerServiceProvider($this->app))->bootingPackage();

    $scheduled = collect(app(Schedule::class)->events())->pluck('description');
    expect($scheduled)->not->toContain('watchtower:alert-digest')
        ->and($scheduled)->toContain('watchtower:cleanup');
});

class WatchtowerTestBrokenInstantAlert extends BlockAlert
{
    public function toMail(object $notifiable): MailMessage
    {
        throw new RuntimeException('mailer down');
    }
}

class WatchtowerTestBrokenDigest extends BlockDigest
{
    public function toMail(object $notifiable): MailMessage
    {
        throw new RuntimeException('mailer down');
    }
}

class WatchtowerTestBlockDuringSendDigest extends BlockDigest
{
    public function toMail(object $notifiable): MailMessage
    {
        digestReblock('198.51.100.1');

        return parent::toMail($notifiable);
    }
}

class WatchtowerTestRecordingChannel
{
    public static int $sent = 0;

    public function send(object $notifiable, BaseNotification $notification): void
    {
        self::$sent++;
    }
}

/**
 * A second run, started by hand, sealing a newer row — and failing to send
 * it — while this one is still sending.
 */
class WatchtowerTestOverlappingRunDigest extends BlockDigest
{
    public function toMail(object $notifiable): MailMessage
    {
        digestRow(['ip' => '198.51.100.2', 'sealed' => true]);

        return parent::toMail($notifiable);
    }
}
