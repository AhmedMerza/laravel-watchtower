<?php

declare(strict_types=1);

use Illuminate\Auth\Events\Failed;
use Illuminate\Foundation\Auth\User;
use Illuminate\Notifications\AnonymousNotifiable;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Notification;
use Illuminate\Support\Facades\Route;
use Watchtower\Listeners\SendBlockAlert;
use Watchtower\Notifications\BlockAlert;
use Watchtower\Notifications\BlockDigest;
use Watchtower\Support\FailureWindow;
use Watchtower\Tests\TestCase;

// Real failed logins through the real counter, so the alert is proven against
// the event AccountTargeting actually fires — not a hand-built one.
beforeAll(function () {
    TestCase::$beforeBoot = function ($app) {
        $app['config']->set('cache.default', 'array');
        $app['config']->set('watchtower.cache.store', 'array');
        $app['config']->set('watchtower.auto_block.enabled', true);
        $app['config']->set('watchtower.auto_block.mode', 'warn');
        $app['config']->set('watchtower.auto_block.account_targeting.one_account.enabled', true);
        $app['config']->set('watchtower.auto_block.account_targeting.one_subnet.enabled', true);
    };
});

afterAll(function () {
    TestCase::$beforeBoot = null;
});

beforeEach(function () {
    config()->set('watchtower.auto_block.account_targeting.one_account.count', 3);
    config()->set('watchtower.auto_block.account_targeting.one_subnet.count', 3);
    config()->set('watchtower.notifications.alerts', [
        'enabled'            => true,
        'routes'             => ['mail' => 'ops@example.com', 'slack' => null],
        'throttle_minutes'   => 60,
        'max_per_window'     => 20,
        'manual'             => false,
        'would_have_blocked' => false,
        'account_targeted'   => true,
        'notification'       => BlockAlert::class,
        'digest'             => [
            'enabled'      => false,
            'at'           => '08:00',
            'instant'      => true,
            'notification' => BlockDigest::class,
        ],
    ]);
    FailureWindow::forget('account_targeting');
    Carbon::setTestNow('2026-10-19 12:00:00');
    Notification::fake();

    Route::post('/login', function () {
        $target = null;

        if (request('user_id') !== null) {
            $target = new User;
            $target->id = (int) request('user_id');
        }

        event(new Failed((string) request('guard', 'web'), $target, ['email' => (string) request('email'), 'password' => 'x']));

        return 'tried';
    });
});

afterEach(function () {
    Carbon::setTestNow();
});

function failAt(string $ip, string $email, ?int $userId = null, string $guard = 'web'): void
{
    test()->withServerVariables(['REMOTE_ADDR' => $ip])
        ->post('/login', ['email' => $email, 'user_id' => $userId, 'guard' => $guard])
        ->assertOk();
}

/** Three addresses failing against account 7 on $guard: one one_account crossing. */
function stuffAccount(string $guard = 'web', string $net = '198.51.100'): void
{
    foreach ([1, 2, 3] as $host) {
        failAt("{$net}.{$host}", 'alice@example.com', 7, $guard);
    }
}

/** @return list<BlockAlert> */
function accountAlerts(): array
{
    return Notification::sent(new AnonymousNotifiable, BlockAlert::class)
        ->filter(fn (BlockAlert $n) => $n->alert['type'] === 'account_targeted')
        ->values()
        ->all();
}

it('alerts when one account fails from enough addresses, naming the account, guard and addresses', function () {
    // Three addresses in three subnets, so one_subnet stays quiet.
    failAt('198.51.100.1', 'alice@example.com', 7);
    failAt('203.0.113.2', 'alice@example.com', 7);
    failAt('192.0.2.3', 'alice@example.com', 7);

    $alerts = accountAlerts();

    expect($alerts)->toHaveCount(1)
        ->and($alerts[0]->alert['ip'])->toBe('7')
        ->and($alerts[0]->alert['scope'])->toBe('web')
        ->and($alerts[0]->alert['context'])->toMatchArray([
            'rule'     => 'one_account',
            'count'    => 3,
            'listed'   => ['198.51.100.1', '203.0.113.2', '192.0.2.3'],
            'unlisted' => 0,
        ])
        ->and($alerts[0]->subject())->toBe('Watchtower: account 7 failed logins from 3 addresses')
        ->and($alerts[0]->lines())->toContain('Account: 7', 'Guard: web', 'Addresses: 198.51.100.1, 203.0.113.2, 192.0.2.3');
});

it('alerts when one subnet fails against enough accounts, listing the existing ones', function () {
    failAt('198.51.100.1', 'a@example.com', 1);
    failAt('198.51.100.2', 'b@example.com');
    failAt('198.51.100.3', 'c@example.com', 3);

    $alerts = accountAlerts();

    expect($alerts)->toHaveCount(1)
        ->and($alerts[0]->alert['ip'])->toBe('198.51.100.0/24')
        ->and($alerts[0]->alert['scope'])->toBeNull()
        ->and($alerts[0]->alert['context'])->toMatchArray(['rule' => 'one_subnet', 'count' => 3, 'listed' => ['1', '3']])
        ->and($alerts[0]->subject())->toBe('Watchtower: subnet 198.51.100.0/24 failed logins against 3 accounts')
        ->and($alerts[0]->lines())->toContain('Existing accounts among them: 1, 3');
});

it('lists at most MAX_LISTED and counts the rest', function () {
    $count = SendBlockAlert::MAX_LISTED + 2;
    config()->set('watchtower.auto_block.account_targeting.one_account.count', $count);

    foreach (range(1, $count) as $n) {
        failAt("10.{$n}.0.1", 'alice@example.com', 7);
    }

    $context = accountAlerts()[0]->alert['context'];

    expect($context['listed'])->toHaveCount(SendBlockAlert::MAX_LISTED)
        ->and($context['unlisted'])->toBe(2)
        ->and(accountAlerts()[0]->lines())->toContain('Addresses: '.implode(', ', $context['listed']).' and 2 more');
});

it('sends nothing with account_targeted alerts off', function () {
    config()->set('watchtower.notifications.alerts.account_targeted', false);

    stuffAccount();

    expect(accountAlerts())->toBe([]);
});

it('throttles per account and guard: the same account again is held, the same id on another guard is not', function () {
    stuffAccount();
    stuffAccount('web', '203.0.113');
    stuffAccount('admin', '192.0.2');

    expect(array_map(fn (BlockAlert $a) => $a->alert['scope'], accountAlerts()))->toBe(['web', 'admin']);
});

it('counts the crossings into the digest, keyed by account and guard', function () {
    config()->set('watchtower.notifications.alerts.digest.enabled', true);

    stuffAccount();
    stuffAccount('web', '203.0.113');

    $row = DB::table('watchtower_alert_digest')->where('type', 'account_targeted')->sole();

    expect($row->ip)->toBe('7')
        ->and($row->scope)->toBe('web')
        ->and((int) $row->events)->toBe(2)
        ->and((int) $row->held_back)->toBe(1);

    $this->artisan('watchtower:alert-digest')->assertSuccessful();

    Notification::assertSentOnDemand(BlockDigest::class, function (BlockDigest $digest) {
        return $digest->digest['totals']['account_targeted'] === 1
            && str_ends_with($digest->subject(), ', 1 accounts or subnets targeted')
            && collect($digest->lines())->contains(fn (string $line) => str_starts_with(
                $line,
                'Account 7 (guard web) targeted (2 times) — Credential stuffing: one account failing from many addresses — 2026-10-19 12:00 — 1 not alerted at the time',
            ));
    });
});
