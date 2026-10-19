<?php

declare(strict_types=1);

use Illuminate\Auth\Events\Failed;
use Illuminate\Cache\ArrayStore;
use Illuminate\Foundation\Auth\User;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Route;
use Watchtower\Events\AccountTargeted;
use Watchtower\Services\AccountTargeting;
use Watchtower\Support\FailureWindow;
use Watchtower\Support\SignalLog;
use Watchtower\Tests\TestCase;

// failed_logins stays off at boot: account targeting has to register the
// Failed listener on its own.
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
    FailureWindow::forget('account_targeting');
    Carbon::setTestNow('2026-10-19 12:00:00');

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

function failLogin(string $ip, string $email, ?int $userId = null, string $guard = 'web'): void
{
    test()->withServerVariables(['REMOTE_ADDR' => $ip])
        ->post('/login', ['email' => $email, 'user_id' => $userId, 'guard' => $guard])
        ->assertOk();
}

it('fires once one account has failed from enough distinct addresses', function () {
    Event::fake([AccountTargeted::class]);

    failLogin('198.51.100.1', 'alice@example.com', 7);
    failLogin('198.51.100.1', 'alice@example.com', 7);
    failLogin('203.0.113.2', 'alice@example.com', 7);

    Event::assertNotDispatched(AccountTargeted::class, fn (AccountTargeted $e) => $e->rule === 'one_account');

    failLogin('192.0.2.3', 'Alice@Example.com ', 7);

    Event::assertDispatched(AccountTargeted::class, fn (AccountTargeted $e) => $e->rule === 'one_account'
        && $e->subject === SignalLog::targetHash(['email' => 'alice@example.com'])
        && $e->members === ['198.51.100.1', '203.0.113.2', '192.0.2.3']
        && $e->targetUserIds === ['7']
        && $e->guard === 'web'
        && $e->windowMinutes === 15);
});

it('logs the crossing', function () {
    $channel = Mockery::mock();
    $channel->shouldReceive('warning')->once()->with(AccountTargeting::MESSAGE, Mockery::on(
        fn (array $context) => $context['rule'] === 'one_account' && $context['count'] === 3 && $context['target_user_ids'] === [],
    ));
    Log::shouldReceive('channel')->andReturn($channel);

    foreach (['198.51.100.1', '203.0.113.2', '192.0.2.3'] as $ip) {
        failLogin($ip, 'nobody@example.com');
    }
});

it('counts addresses in one IPv6 block as one', function () {
    Event::fake([AccountTargeted::class]);

    foreach (['2001:db8::1', '2001:db8::2', '2001:db8::3', '198.51.100.1'] as $ip) {
        failLogin($ip, 'alice@example.com');
    }

    Event::assertNotDispatched(AccountTargeted::class, fn (AccountTargeted $e) => $e->rule === 'one_account');
});

it('keeps the same identifier on another guard apart', function () {
    Event::fake([AccountTargeted::class]);

    failLogin('198.51.100.1', 'alice@example.com', guard: 'web');
    failLogin('203.0.113.2', 'alice@example.com', guard: 'admin');
    failLogin('192.0.2.3', 'alice@example.com', guard: 'web');

    Event::assertNotDispatched(AccountTargeted::class, fn (AccountTargeted $e) => $e->rule === 'one_account');
});

it('starts over once the window has passed', function () {
    Event::fake([AccountTargeted::class]);

    failLogin('198.51.100.1', 'alice@example.com');
    failLogin('203.0.113.2', 'alice@example.com');
    Carbon::setTestNow(now()->addMinutes(15));
    failLogin('192.0.2.3', 'alice@example.com');

    Event::assertNotDispatched(AccountTargeted::class, fn (AccountTargeted $e) => $e->rule === 'one_account');
});

it('starts over at a crossing, so the next event takes a full count', function () {
    Event::fake([AccountTargeted::class]);

    foreach (['198.51.100.1', '203.0.113.2', '192.0.2.3', '192.0.2.4', '192.0.2.5'] as $ip) {
        failLogin($ip, 'alice@example.com');
    }

    Event::assertDispatchedTimes(AccountTargeted::class, 1);

    failLogin('192.0.2.6', 'alice@example.com');

    Event::assertDispatchedTimes(AccountTargeted::class, 2);
});

it('fires once one subnet has failed against enough distinct accounts', function () {
    Event::fake([AccountTargeted::class]);

    failLogin('198.51.100.1', 'a@example.com', 1);
    failLogin('198.51.100.200', 'b@example.com');
    failLogin('198.51.101.1', 'c@example.com');

    Event::assertNotDispatched(AccountTargeted::class);

    failLogin('198.51.100.9', 'c@example.com', 3);

    Event::assertDispatched(AccountTargeted::class, fn (AccountTargeted $e) => $e->rule === 'one_subnet'
        && $e->subject === '198.51.100.0/24'
        && count($e->members) === 3
        && $e->targetUserIds === ['1', '3']
        && $e->guard === null);
});

it('groups IPv4 by the configured prefix', function () {
    Event::fake([AccountTargeted::class]);
    config()->set('watchtower.auto_block.account_targeting.one_subnet.ipv4_prefix', 16);

    failLogin('198.51.1.1', 'a@example.com');
    failLogin('198.51.2.1', 'b@example.com');
    failLogin('198.51.3.1', 'c@example.com');

    Event::assertDispatched(AccountTargeted::class, fn (AccountTargeted $e) => $e->subject === '198.51.0.0/16');
});

it('counts nothing with every rule off', function () {
    Event::fake([AccountTargeted::class]);
    config()->set('watchtower.auto_block.account_targeting.one_account.enabled', false);
    config()->set('watchtower.auto_block.account_targeting.one_subnet.enabled', false);

    foreach (['198.51.100.1', '198.51.100.2', '198.51.100.3'] as $i => $ip) {
        failLogin($ip, "user{$i}@example.com");
        failLogin($ip, 'alice@example.com');
    }

    Event::assertNotDispatched(AccountTargeted::class);
    expect(Cache::store('array')->get('watchtower:blacklist:targeted:one_subnet:198.51.100.0/24'))->toBeNull();
});

it('lets the login through when the cache is down, and says so once', function () {
    Cache::extend('targeting-fails', fn () => Cache::repository(new class extends ArrayStore
    {
        public function get($key): mixed
        {
            throw new RuntimeException('cache down');
        }
    }));
    config()->set('cache.stores.targeting-fails', ['driver' => 'targeting-fails']);
    config()->set('watchtower.cache.store', 'targeting-fails');

    $channel = Mockery::mock();
    $channel->shouldReceive('error')->once()->with(Mockery::pattern('/account targeting failed/'), Mockery::any());
    Log::shouldReceive('channel')->andReturn($channel);

    failLogin('198.51.100.1', 'alice@example.com');
    failLogin('198.51.100.2', 'alice@example.com');
});

it('replays the signal log to the events that fired live', function () {
    Event::fake([AccountTargeted::class]);
    config()->set('watchtower.auto_block.signal_log.enabled', true);
    config()->set('watchtower.auto_block.detectors.failed_logins.enabled', true);
    config()->set('watchtower.auto_block.detectors.failed_logins.count', 1000);

    $at = function (int $seconds, string $ip, string $email, ?int $userId = null) {
        Carbon::setTestNow(Carbon::parse('2026-10-19 08:00:00')->addSeconds($seconds));
        failLogin($ip, $email, $userId);
    };

    // One account from four addresses: a crossing at the third, and the
    // fourth opens the next window.
    foreach (['198.51.100.1', '203.0.113.2', '192.0.2.3', '192.0.2.4'] as $i => $ip) {
        $at($i, $ip, 'alice@example.com', 7);
    }

    // Two addresses, a gap past the window, two more: no crossing.
    foreach ([0, 10, 1000, 1010] as $i => $s) {
        $at(100 + $s, "192.0.2.1{$i}", 'bob@example.com');
    }

    // One /24 against three accounts, then six more in a second /24 — two
    // crossings there.
    foreach (['a', 'b', 'c'] as $i => $name) {
        $at(3000 + $i, '198.18.0.'.($i + 1), "{$name}@example.com");
    }

    foreach (range(1, 6) as $i) {
        $at(4000 + $i, '198.18.5.1', "spray{$i}@example.com");
    }

    app(SignalLog::class)->flush();
    Carbon::setTestNow('2026-10-19 12:00:00');

    $live = [];

    foreach (Event::dispatched(AccountTargeted::class) as [$event]) {
        $live[$event->rule][$event->subject] = ($live[$event->rule][$event->subject] ?? 0) + 1;
    }

    expect(Artisan::call('watchtower:simulate', ['--accounts' => true, '--json' => true]))->toBe(0);
    $json = json_decode(Artisan::output(), true, flags: JSON_THROW_ON_ERROR);

    $replayed = [];

    foreach ($json['account_targeting'] as $rule => $result) {
        foreach ($result['subjects'] as $subject) {
            $replayed[$rule][$subject['subject']] = $subject['crossings'];
        }
    }

    foreach ([&$live, &$replayed] as &$byRule) {
        ksort($byRule);
        array_walk($byRule, static fn (array &$subjects) => ksort($subjects));
    }
    unset($byRule);

    expect($replayed)->toBe($live)
        ->and($live['one_account'])->toBe([SignalLog::targetHash(['email' => 'alice@example.com']) => 1])
        ->and($live['one_subnet'])->toBe(['198.18.0.0/24' => 1, '198.18.5.0/24' => 2]);
});

it('replays at another count and window', function () {
    config()->set('watchtower.auto_block.signal_log.enabled', true);

    $hash = SignalLog::targetHash(['email' => 'alice@example.com']);

    foreach ([0, 20, 40] as $i => $minutes) {
        DB::table(SignalLog::TABLE)->insert([
            'detector'    => 'failed_logins',
            'ip'          => "198.51.100.{$i}",
            'target_hash' => $hash,
            'guard'       => 'web',
            'occurred_at' => now()->subHours(2)->addMinutes($minutes),
        ]);
    }

    $crossings = function (array $options): array {
        expect(Artisan::call('watchtower:simulate', ['--accounts' => 'one_account', '--json' => true, ...$options]))->toBe(0);

        return json_decode(Artisan::output(), true, flags: JSON_THROW_ON_ERROR)['account_targeting']['one_account']['subjects'];
    };

    expect($crossings([]))->toBe([])
        ->and($crossings(['--window' => '60'])[0])->toMatchArray(['subject' => $hash, 'guard' => 'web', 'crossings' => 1, 'members' => 3])
        ->and($crossings(['--count' => '2', '--window' => '30'])[0]['crossings'])->toBe(1);
});

it('refuses what it cannot replay', function (array $options, string $message) {
    config()->set('watchtower.auto_block.signal_log.enabled', true);
    DB::table(SignalLog::TABLE)->insert(['detector' => 'failed_logins', 'ip' => '198.51.100.1', 'occurred_at' => now()]);

    expect(Artisan::call('watchtower:simulate', ['--accounts' => true, ...$options]))->toBe(1)
        ->and(Artisan::output())->toContain($message);
})->with([
    'an unknown rule'  => [['--accounts' => 'one_city'], 'one_account or one_subnet'],
    'two rules, count' => [['--count' => '5'], 'replay one rule'],
    'shared IP users'  => [['--accounts' => 'one_account', '--shared-ip-users' => '3'], 'no shared-IP guard'],
    'with --detector'  => [['--detector' => 'failed_logins'], 'drop --rule and --detector'],
]);

it('says so when the signal log is off', function () {
    config()->set('watchtower.auto_block.signal_log.enabled', false);

    expect(Artisan::call('watchtower:simulate', ['--accounts' => true]))->toBe(1)
        ->and(Artisan::output())->toContain('the signal log is off');
});

it('prints a table per rule', function () {
    config()->set('watchtower.auto_block.signal_log.enabled', true);

    foreach (['a', 'b', 'c'] as $i => $name) {
        DB::table(SignalLog::TABLE)->insert([
            'detector'       => 'failed_logins',
            'ip'             => '198.51.100.'.($i + 1),
            'target_hash'    => SignalLog::targetHash(['email' => "{$name}@example.com"]),
            'target_user_id' => (string) ($i + 1),
            'occurred_at'    => now()->subMinutes(10 - $i),
        ]);
    }

    expect(Artisan::call('watchtower:simulate', ['--accounts' => true]))->toBe(0);

    expect(Artisan::output())
        ->toContain('one_account — 3 distinct addresses per account in 15 min (on)')
        ->toContain('No crossings.')
        ->toContain('one_subnet — 3 distinct accounts per subnet (IPv4 /24) in 15 min (on)')
        ->toContain('198.51.100.0/24')
        ->toContain('1, 2, 3');
});
