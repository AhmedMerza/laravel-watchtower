<?php

declare(strict_types=1);

use Illuminate\Console\Scheduling\Schedule;
use Illuminate\Notifications\AnonymousNotifiable;
use Illuminate\Notifications\Messages\MailMessage;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Notification;
use Illuminate\Support\Facades\Schema;
use Symfony\Component\Mime\Email;
use Watchtower\Console\Commands\AlertDigestCommand;
use Watchtower\Enums\BlockSource;
use Watchtower\Notifications\BlockAlert;
use Watchtower\Notifications\BlockDigest;
use Watchtower\Services\BlacklistService;
use Watchtower\Tests\TestCase;

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

function digestBlock(string $ip): void
{
    app(BlacklistService::class)->block($ip, ['reason' => 'Scanner probe', 'source' => BlockSource::Auto]);
}

function digestReblock(string $ip): void
{
    app(BlacklistService::class)->unblock($ip);
    digestBlock($ip);
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

it('records every event, including the ones the throttle held back', function () {
    Notification::fake();

    digestBlock('198.51.100.1');
    digestReblock('198.51.100.1');

    Notification::assertSentOnDemandTimes(BlockAlert::class, 1);
    expect(DB::table('watchtower_alert_digest')->orderBy('id')->pluck('sent')->map(fn ($s) => (bool) $s)->all())
        ->toBe([true, false]);
});

it('records what the cap held back', function () {
    Notification::fake();
    config()->set('watchtower.notifications.alerts.max_per_window', 1);

    digestBlock('198.51.100.1');
    digestBlock('198.51.100.2');

    expect(DB::table('watchtower_alert_digest')->where('sent', false)->pluck('ip')->all())->toBe(['198.51.100.2']);
});

it('records a near miss under its /64, saying why it was not blocked', function () {
    Notification::fake();

    $this->withServerVariables(['REMOTE_ADDR' => '2001:db8:1:2::9'])->get('/.env');

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
    expect((bool) DB::table('watchtower_alert_digest')->sole()->sent)->toBeFalse();
});

it('records nothing with the digest off', function () {
    Notification::fake();
    config()->set('watchtower.notifications.alerts.digest.enabled', false);

    digestBlock('198.51.100.1');

    Notification::assertSentOnDemandTimes(BlockAlert::class, 1);
    expect(DB::table('watchtower_alert_digest')->count())->toBe(0);
});

it('keeps the block when the digest table is missing', function () {
    Notification::fake();
    Schema::drop('watchtower_alert_digest');
    Log::shouldReceive('channel')->andReturnSelf();
    Log::shouldReceive('warning')->once()->withArgs(fn (string $msg) => $msg === 'Watchtower: could not record the alert for the digest');

    digestBlock('198.51.100.1');

    $this->assertDatabaseHas('blacklisted_ips', ['ip' => '198.51.100.1']);
    Notification::assertSentOnDemandTimes(BlockAlert::class, 1);
});

it('mails one digest grouped by address, then deletes what it sent', function () {
    config()->set('watchtower.notifications.alerts.max_per_window', 1);

    digestBlock('198.51.100.1');
    digestReblock('198.51.100.1');
    digestReblock('198.51.100.1');
    digestBlock('198.51.100.2');
    $this->withServerVariables(['REMOTE_ADDR' => '203.0.113.9'])->get('/.env');

    // The instant alerts: one block (the cap holds the second address back
    // and the throttle the repeat), one near miss — a separate kind.
    expect(sentMail())->toHaveCount(2);
    app('mailer')->getSymfonyTransport()->flush();

    $this->artisan('watchtower:alert-digest')->assertSuccessful();

    $mail = sentMail();
    expect($mail)->toHaveCount(1);

    $body = $mail[0]->getTextBody();
    expect($mail[0]->getSubject())->toBe('Watchtower digest: 2 blocked, 1 would have been')
        ->and($mail[0]->getTo()[0]->getAddress())->toBe('ops@example.com')
        ->and($body)->toContain('Blocked 198.51.100.1 (3 times) — Scanner probe — scope: whole app')
        ->and($body)->toContain('2 not alerted at the time (throttle or cap)')
        ->and($body)->toContain('Would have blocked 203.0.113.9')
        ->and($body)->toContain('not blocked because: warn mode')
        ->and(strpos($body, '198.51.100.1'))->toBeLessThan(strpos($body, '198.51.100.2'))
        ->and(strpos($body, '198.51.100.2'))->toBeLessThan(strpos($body, '203.0.113.9'));

    expect(DB::table('watchtower_alert_digest')->count())->toBe(0);
});

it('sends nothing when there is nothing to report', function () {
    Notification::fake();

    $this->artisan('watchtower:alert-digest')->assertSuccessful();

    Notification::assertNothingSent();
});

it('keeps the rows when the digest goes out on no channel', function () {
    config()->set('watchtower.notifications.alerts.digest.instant', false);
    config()->set('watchtower.notifications.alerts.digest.notification', WatchtowerTestBrokenDigest::class);
    digestBlock('198.51.100.1');

    $this->artisan('watchtower:alert-digest')->assertFailed();

    expect(sentMail())->toBe([])
        ->and(DB::table('watchtower_alert_digest')->count())->toBe(1);
});

it('leaves rows written while the digest was sending for the next one', function () {
    config()->set('watchtower.notifications.alerts.digest.instant', false);
    config()->set('watchtower.notifications.alerts.digest.notification', WatchtowerTestBlockDuringSendDigest::class);
    digestBlock('198.51.100.1');

    $this->artisan('watchtower:alert-digest')->assertSuccessful();

    expect(DB::table('watchtower_alert_digest')->pluck('ip')->all())->toBe(['198.51.100.2']);
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

it('does not call events held back when instant alerts are off', function () {
    $mail = (new BlockDigest([
        'since'   => '2026-10-07 08:00:00',
        'instant' => false,
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
        'url'     => null,
    ]))->toMail(new AnonymousNotifiable);

    expect($mail)->toBeInstanceOf(MailMessage::class)
        ->and($mail->introLines)->toBe([
            'Since 2026-10-07 08:00.',
            'Blocked 198.51.100.1 — Scanner probe — scope: auth — 2026-10-07 09:12',
        ])
        ->and($mail->actionUrl)->toBeNull();
});

it('schedules the digest daily at the configured time', function () {
    $event = collect(app(Schedule::class)->events())
        ->first(fn ($event) => $event->description === 'watchtower:alert-digest');

    expect($event)->not->toBeNull()
        ->and($event->expression)->toBe('30 7 * * *');
});

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
        digestBlock('198.51.100.2');

        return parent::toMail($notifiable);
    }
}
