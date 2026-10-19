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
    $channel->shouldReceive('warning')->once()->with(AccountTargeting::MESSAGE, Mockery::on(fn (array $context) => $context === [
        'rule'            => 'one_account',
        'subject'         => SignalLog::targetHash(['email' => 'alice@example.com']),
        'count'           => 3,
        'window_minutes'  => 15,
        'members'         => ['198.51.100.1', '203.0.113.2', '192.0.2.3'],
        'target_user_ids' => ['7'],
        'guard'           => 'web',
    ]));
    Log::shouldReceive('channel')->andReturn($channel);

    foreach (['198.51.100.1', '203.0.113.2', '192.0.2.3'] as $ip) {
        failLogin($ip, 'alice@example.com', 7);
    }
});

it('counts addresses in one IPv6 block as one', function () {
    Event::fake([AccountTargeted::class]);

    foreach (['2001:db8::1', '2001:db8::2', '2001:db8::3', '198.51.100.1'] as $ip) {
        failLogin($ip, 'alice@example.com', 7);
    }

    Event::assertNotDispatched(AccountTargeted::class, fn (AccountTargeted $e) => $e->rule === 'one_account');
});

it('keeps the same identifier on another guard apart', function () {
    Event::fake([AccountTargeted::class]);

    failLogin('198.51.100.1', 'alice@example.com', 7, 'web');
    failLogin('203.0.113.2', 'alice@example.com', 7, 'admin');
    failLogin('192.0.2.3', 'alice@example.com', 7, 'web');

    Event::assertNotDispatched(AccountTargeted::class, fn (AccountTargeted $e) => $e->rule === 'one_account');
});

it('starts over once the window has passed', function () {
    Event::fake([AccountTargeted::class]);

    failLogin('198.51.100.1', 'alice@example.com', 7);
    failLogin('203.0.113.2', 'alice@example.com', 7);
    Carbon::setTestNow(now()->addMinutes(15));
    failLogin('192.0.2.3', 'alice@example.com', 7);

    Event::assertNotDispatched(AccountTargeted::class, fn (AccountTargeted $e) => $e->rule === 'one_account');
});

it('starts over at a crossing, so the next event takes a full count', function () {
    Event::fake([AccountTargeted::class]);

    foreach (['198.51.100.1', '203.0.113.2', '192.0.2.3', '192.0.2.4', '192.0.2.5'] as $ip) {
        failLogin($ip, 'alice@example.com', 7);
    }

    Event::assertDispatchedTimes(AccountTargeted::class, 1);

    failLogin('192.0.2.6', 'alice@example.com', 7);

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
    config()->set('watchtower.auto_block.account_targeting.one_subnet.ipv4_prefix', 20);

    $at = function (int $seconds, string $ip, string $email, ?int $userId = null, string $guard = 'web') {
        Carbon::setTestNow(Carbon::parse('2026-10-19 08:00:00')->addSeconds($seconds));
        failLogin($ip, $email, $userId, $guard);
    };

    // One account from four addresses: a crossing at the third, and the
    // fourth opens the next window.
    foreach (['198.51.100.1', '203.0.113.2', '192.0.2.3', '192.0.2.4'] as $i => $ip) {
        $at($i, $ip, 'alice@example.com', 7);
    }

    // Two addresses, a gap past the window, two more: no crossing.
    foreach ([0, 10, 1000, 1010] as $i => $s) {
        $at(100 + $s, "192.0.2.1{$i}", 'bob@example.com', 8);
    }

    // Three addresses in one /64 and one more are two addresses; the same
    // account on two guards is two accounts. No crossing in either.
    foreach (['2001:db8::1', '2001:db8::2', '2001:db8::3', '198.51.100.9'] as $i => $ip) {
        $at(2000 + $i, $ip, 'carol@example.com', 9);
    }

    foreach (['web', 'admin', 'web'] as $i => $guard) {
        $at(2500 + $i, "203.0.113.2{$i}", 'dave@example.com', 10, $guard);
    }

    // One /20 against three accounts, from addresses in different /24s;
    // then six made-up names from one /64 — two crossings there.
    foreach (['a', 'b', 'c'] as $i => $name) {
        $at(3000 + $i, "198.18.{$i}.1", "{$name}@example.com");
    }

    foreach (range(1, 6) as $i) {
        $at(4000 + $i, "2001:db8:5::{$i}", "spray{$i}@example.com");
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
        ->and($live['one_subnet'])->toBe(['198.18.0.0/20' => 1, '2001:db8:5::/64' => 2]);
});

it('replays at another count and window', function () {
    config()->set('watchtower.auto_block.signal_log.enabled', true);

    $hash = SignalLog::targetHash(['email' => 'alice@example.com']);

    foreach ([0, 20, 40] as $i => $minutes) {
        DB::table(SignalLog::TABLE)->insert([
            'detector'    => 'failed_logins',
            'ip'          => "198.51.100.{$i}",
            'target_hash'    => $hash,
            'target_user_id' => '7',
            'guard'          => 'web',
            'occurred_at'    => now()->subHours(2)->addMinutes($minutes),
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
    DB::table(SignalLog::TABLE)->insert(['detector' => 'failed_logins', 'ip' => '198.51.100.1', 'target_hash' => str_repeat('a', 64), 'occurred_at' => now()]);

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

function loggedFailure(string $ip, string $email, ?string $userId, float $minutesAgo, string $detector = 'failed_logins', ?string $guard = 'web'): void
{
    DB::table(SignalLog::TABLE)->insert([
        'detector'       => $detector,
        'ip'             => $ip,
        'target_hash'    => SignalLog::targetHash(['email' => $email]),
        'target_user_id' => $userId,
        'guard'          => $guard,
        'occurred_at'    => now()->subSeconds((int) round($minutesAgo * 60)),
    ]);
}

function accountsJson(array $options = []): array
{
    expect(Artisan::call('watchtower:simulate', ['--accounts' => true, '--json' => true, ...$options]))->toBe(0);

    return json_decode(Artisan::output(), true, flags: JSON_THROW_ON_ERROR);
}

it('leaves made-up accounts to one_subnet', function () {
    Event::fake([AccountTargeted::class]);

    foreach (['198.51.100.1', '203.0.113.2', '192.0.2.3'] as $ip) {
        failLogin($ip, 'nobody@example.com');
    }

    foreach (['ghost1', 'ghost2', 'ghost3'] as $name) {
        failLogin('198.18.0.1', "{$name}@example.com");
    }

    Event::assertDispatchedTimes(AccountTargeted::class, 1);
    Event::assertDispatched(AccountTargeted::class, fn (AccountTargeted $e) => $e->rule === 'one_subnet' && $e->targetUserIds === []);
    expect(Cache::store('array')->get('watchtower:blacklist:targeted:one_account:web:'.SignalLog::targetHash(['email' => 'nobody@example.com'])))->toBeNull();
});

it('counts only the rules that are on', function () {
    Event::fake([AccountTargeted::class]);
    config()->set('watchtower.auto_block.account_targeting.one_account.enabled', false);

    foreach (['198.51.100.1', '203.0.113.2', '192.0.2.3'] as $ip) {
        failLogin($ip, 'alice@example.com', 7);
    }

    foreach (['a', 'b', 'c'] as $name) {
        failLogin('198.18.0.1', "{$name}@example.com");
    }

    Event::assertDispatchedTimes(AccountTargeted::class, 1);
    Event::assertDispatched(AccountTargeted::class, fn (AccountTargeted $e) => $e->rule === 'one_subnet');
});

it('counts nothing with auto-block switched off', function () {
    Event::fake([AccountTargeted::class]);
    config()->set('watchtower.auto_block.enabled', false);

    foreach (['a', 'b', 'c'] as $i => $name) {
        failLogin('198.51.100.'.($i + 1), "{$name}@example.com", 7);
        failLogin('198.51.100.'.($i + 1), 'alice@example.com', 7);
    }

    Event::assertNotDispatched(AccountTargeted::class);
    expect(Cache::store('array')->get('watchtower:blacklist:targeted:one_subnet:198.51.100.0/24'))->toBeNull()
        ->and(AccountTargeting::enabled())->toBeFalse();
});

it('skips a failed login with no identifier to hash', function () {
    Route::post('/login-password-only', function () {
        event(new Failed('web', null, ['password' => 'x']));

        return 'tried';
    });

    foreach (['198.51.100.1', '198.51.100.2', '198.51.100.3'] as $ip) {
        $this->withServerVariables(['REMOTE_ADDR' => $ip])->post('/login-password-only')->assertOk();
    }

    expect(Cache::store('array')->get('watchtower:blacklist:targeted:one_subnet:198.51.100.0/24'))->toBeNull();
});

it('writes nothing for a member already in a running window', function () {
    $store = new class extends ArrayStore
    {
        public int $puts = 0;

        public function put($key, $value, $seconds): bool
        {
            // The blocklist lookups share this store; only the windows count.
            $this->puts += (int) str_contains((string) $key, ':targeted:');

            return parent::put($key, $value, $seconds);
        }
    };
    Cache::extend('counting', fn () => Cache::repository($store));
    config()->set('cache.stores.counting', ['driver' => 'counting']);
    config()->set('watchtower.cache.store', 'counting');
    config()->set('watchtower.auto_block.account_targeting.one_subnet.enabled', false);

    failLogin('198.51.100.1', 'alice@example.com', 7);
    failLogin('198.51.100.1', 'alice@example.com', 7);
    failLogin('198.51.100.1', 'alice@example.com', 7);

    expect($store->puts)->toBe(1);
});

it('starts a fresh window over a stored value that is not one', function (mixed $stored) {
    Event::fake([AccountTargeted::class]);
    Cache::store('array')->put('watchtower:blacklist:targeted:one_account:web:'.SignalLog::targetHash(['email' => 'alice@example.com']), $stored, 60);

    foreach (['198.51.100.1', '203.0.113.2', '192.0.2.3'] as $ip) {
        failLogin($ip, 'alice@example.com', 7);
    }

    Event::assertDispatched(AccountTargeted::class, fn (AccountTargeted $e) => $e->rule === 'one_account' && count($e->members) === 3);
})->with([
    'a string'           => ['garbage'],
    'no expiry'          => [['members' => []]],
    'a string expiry'    => [['expires' => 'x', 'members' => []]],
    'members not a list' => [['expires' => PHP_INT_MAX, 'members' => 'x']],
]);

it('lets an app listener that throws fail on its own, after both rules counted', function () {
    Event::listen(AccountTargeted::class, function () {
        throw new RuntimeException('listener broke');
    });

    failLogin('198.51.100.1', 'alice@example.com', 7);
    failLogin('203.0.113.2', 'alice@example.com', 7);

    $this->withServerVariables(['REMOTE_ADDR' => '192.0.2.3'])
        ->post('/login', ['email' => 'alice@example.com', 'user_id' => 7])
        ->assertServerError();

    // one_subnet ran after one_account crossed, and kept its count; and the
    // listener's error isn't taken for the cache failing.
    expect(Cache::store('array')->get('watchtower:blacklist:targeted:one_subnet:192.0.2.0/24'))->not->toBeNull()
        ->and(FailureWindow::isOpen('account_targeting'))->toBeFalse();
});

it('defaults and clamps the settings', function (array $configured, array $expected) {
    config()->set('watchtower.auto_block.account_targeting.one_subnet', $configured);

    expect(AccountTargeting::settings('one_subnet'))->toBe($expected);
})->with([
    'defaults'        => [[], ['count' => 20, 'window_minutes' => 15, 'ipv4_prefix' => 24]],
    'too small'       => [['count' => 1, 'window_minutes' => 0, 'ipv4_prefix' => 8], ['count' => 2, 'window_minutes' => 1, 'ipv4_prefix' => 24]],
    'too large'       => [['count' => 5000, 'window_minutes' => 60, 'ipv4_prefix' => 33], ['count' => 1000, 'window_minutes' => 60, 'ipv4_prefix' => 24]],
    'the bounds'      => [['count' => 1000, 'ipv4_prefix' => 16], ['count' => 1000, 'window_minutes' => 15, 'ipv4_prefix' => 16]],
    'the upper bound' => [['ipv4_prefix' => 32], ['count' => 20, 'window_minutes' => 15, 'ipv4_prefix' => 32]],
]);

it('keys nothing for an address that is not one', function () {
    expect(AccountTargeting::keys('one_account', 'not-an-ip', str_repeat('a', 64), '7', 'web', 24))->toBeNull()
        ->and(AccountTargeting::keys('one_subnet', 'not-an-ip', str_repeat('a', 64), null, null, 24))->toBeNull()
        ->and(AccountTargeting::keys('one_account', '198.51.100.1', str_repeat('a', 64), null, 'web', 24))->toBeNull()
        ->and(AccountTargeting::keys('one_subnet', '::ffff:198.51.100.1', str_repeat('a', 64), null, null, 24))->toBe(['198.51.100.0/24', str_repeat('a', 64)]);
});

it('replays only failed logins with an account hash from a real address', function () {
    config()->set('watchtower.auto_block.signal_log.enabled', true);

    foreach (['a', 'b'] as $i => $name) {
        loggedFailure('198.51.100.'.($i + 1), "{$name}@example.com", null, 10 - $i);
    }

    // None of these may make the third account.
    loggedFailure('198.51.100.3', 'c@example.com', null, 7, 'login_lockouts');
    loggedFailure('not-an-ip', 'd@example.com', null, 6);
    DB::table(SignalLog::TABLE)->insert(['detector' => 'failed_logins', 'ip' => '198.51.100.4', 'occurred_at' => now()->subMinutes(5)]);
    loggedFailure('198.51.100.5', 'e@example.com', null, 60 * 24 * 8);

    expect(accountsJson()['account_targeting']['one_subnet']['subjects'])->toBe([]);

    loggedFailure('198.51.100.6', 'f@example.com', null, 4);

    expect(accountsJson()['account_targeting']['one_subnet']['subjects'])->toHaveCount(1);
});

it('keeps live windows when it sweeps stale ones', function () {
    config()->set('watchtower.auto_block.signal_log.enabled', true);

    loggedFailure('198.51.100.1', 'a@example.com', null, 10);
    loggedFailure('198.51.100.2', 'b@example.com', null, 10);

    // Past the sweep threshold: 1001 more subnets, all still open.
    $rows = [];
    foreach (range(1, 1001) as $i) {
        $rows[] = ['detector' => 'failed_logins', 'ip' => '10.'.intdiv($i, 256).'.'.($i % 256).'.1', 'target_hash' => str_repeat('b', 64), 'occurred_at' => now()->subMinutes(9)];
    }
    DB::table(SignalLog::TABLE)->insert($rows);

    loggedFailure('198.51.100.3', 'c@example.com', null, 8);

    expect(collect(accountsJson()['account_targeting']['one_subnet']['subjects'])->pluck('subject')->all())->toBe(['198.51.100.0/24']);
});

it('reports what it judged by, and sorts by crossings', function () {
    config()->set('watchtower.auto_block.signal_log.enabled', true);
    config()->set('watchtower.auto_block.account_targeting.one_account.enabled', false);

    foreach (range(1, 6) as $i) {
        loggedFailure('198.18.5.1', "s{$i}@example.com", (string) $i, 30 - $i);
    }

    foreach (['a', 'b', 'c'] as $i => $name) {
        loggedFailure('198.18.0.1', "{$name}@example.com", null, 20 - $i);
    }

    $json = accountsJson();

    expect($json)->toHaveKeys(['from', 'to', 'days', 'signal_log_oldest'])
        ->and($json['days'])->toBe(7)
        ->and(array_diff_key($json['account_targeting']['one_account'], ['subjects' => true]))
        ->toBe(['enabled' => false, 'count' => 3, 'window_minutes' => 15, 'ipv4_prefix' => null, 'overridden' => false])
        ->and(array_diff_key($json['account_targeting']['one_subnet'], ['subjects' => true]))
        ->toBe(['enabled' => true, 'count' => 3, 'window_minutes' => 15, 'ipv4_prefix' => 24, 'overridden' => false]);

    [$first, $second] = $json['account_targeting']['one_subnet']['subjects'];

    expect($first)->toMatchArray(['subject' => '198.18.5.0/24', 'guard' => null, 'crossings' => 2, 'members' => 6, 'target_user_ids' => ['1', '2', '3', '4', '5', '6']])
        ->and($first['first_at'] < $first['last_at'])->toBeTrue()
        ->and($second)->toMatchArray(['subject' => '198.18.0.0/24', 'crossings' => 1, 'target_user_ids' => []]);

    expect(accountsJson(['--accounts' => 'one_subnet', '--count' => '6'])['account_targeting']['one_subnet'])
        ->toMatchArray(['count' => 6, 'overridden' => true]);
});

it('refuses a log with no failed logins to replay', function () {
    config()->set('watchtower.auto_block.signal_log.enabled', true);
    DB::table(SignalLog::TABLE)->insert(['detector' => 'scanner_paths', 'ip' => '198.51.100.1', 'occurred_at' => now()]);

    expect(Artisan::call('watchtower:simulate', ['--accounts' => true]))->toBe(1)
        ->and(Artisan::output())->toContain('holds none with an account hash');
});

it('prints the account table and truncates long lists', function () {
    config()->set('watchtower.auto_block.signal_log.enabled', true);

    foreach (['198.51.100.1', '203.0.113.2', '192.0.2.3'] as $i => $ip) {
        loggedFailure($ip, 'alice@example.com', '7', 30 - $i, guard: 'admin');
    }

    foreach (range(1, 7) as $i) {
        loggedFailure('198.18.9.1', "u{$i}@example.com", (string) $i, 25 - $i / 10);
    }

    foreach (range(1, 26) as $n) {
        foreach (['a', 'b', 'c'] as $i => $name) {
            loggedFailure("10.0.{$n}.1", "{$name}{$n}@example.com", null, 20 - $i / 10);
        }
    }

    expect(Artisan::call('watchtower:simulate', ['--accounts' => true]))->toBe(0);
    $out = Artisan::output();

    expect($out)
        ->toContain('Guard')
        ->toContain(substr((string) SignalLog::targetHash(['email' => 'alice@example.com']), 0, 12).'…')
        ->toContain('admin')
        ->toContain('1, 2, 3, 4, 5, …')
        ->toContain('… and 2 more. --json lists them all.');
});
