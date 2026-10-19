<?php

declare(strict_types=1);

use Illuminate\Auth\Events\Failed;
use Illuminate\Auth\Events\Lockout;
use Illuminate\Foundation\Auth\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Schema;
use Watchtower\Services\AutoBlockService;
use Watchtower\Services\BlacklistService;
use Watchtower\Support\FailureWindow;
use Watchtower\Support\SignalLog;
use Watchtower\Tests\TestCase;

// The detector middleware is only added to the stack when a detector is on,
// so they have to be switched on before the provider boots.
beforeAll(function () {
    TestCase::$beforeBoot = function ($app) {
        $app['config']->set('cache.default', 'array');
        $app['config']->set('watchtower.cache.store', 'array');
        $app['config']->set('watchtower.auto_block.enabled', true);
        $app['config']->set('watchtower.auto_block.mode', 'warn');

        foreach (['failed_logins', 'login_lockouts', 'scanner_paths', 'response_bursts'] as $detector) {
            $app['config']->set("watchtower.auto_block.detectors.{$detector}.enabled", true);
        }
    };
});

afterAll(function () {
    TestCase::$beforeBoot = null;
});

beforeEach(function () {
    config()->set('watchtower.auto_block.signal_log.enabled', true);
    config()->set('watchtower.auto_block.detectors.response_bursts.count', 100);
    config()->set('watchtower.auto_block.detectors.failed_logins.count', 100);
    FailureWindow::forget('signal_log');
});

function signals(?string $detector = null): array
{
    return DB::table(SignalLog::TABLE)
        ->when($detector, fn ($query) => $query->where('detector', $detector))
        ->orderBy('id')
        ->get()->map(fn ($row) => (array) $row)->all();
}

it('writes nothing while switched off', function () {
    config()->set('watchtower.auto_block.signal_log.enabled', false);

    $this->withServerVariables(['REMOTE_ADDR' => '203.0.113.1'])->get('/.env');

    expect(signals())->toBe([]);
});

it('logs a scanner probe with its path', function () {
    $this->withServerVariables(['REMOTE_ADDR' => '203.0.113.2'])->get('/.env');

    // The probe 404s too, so response_bursts counts it as well — one row per
    // detector that counted.
    expect(collect(signals())->pluck('detector')->sort()->values()->all())->toBe(['response_bursts', 'scanner_paths'])
        ->and(signals('scanner_paths')[0])->toMatchArray([
            'detector'    => 'scanner_paths',
            'ip'          => '203.0.113.2',
            'user_id'     => null,
            'path'        => '.env',
            'status'      => null,
            'target_hash' => null,
        ]);
});

it('logs the signed-in user on a counted request', function () {
    $user = new User;
    $user->id = 7;

    $this->actingAs($user)->withServerVariables(['REMOTE_ADDR' => '203.0.113.3'])->get('/.env');

    expect(signals('scanner_paths')[0]['user_id'])->toBe('7');
});

it('logs a response burst signal with its status, below the threshold too', function () {
    Route::get('/orders/{id}', fn () => abort(404));

    $this->withServerVariables(['REMOTE_ADDR' => '203.0.113.4'])->get('/orders/1');
    $this->withServerVariables(['REMOTE_ADDR' => '203.0.113.4'])->get('/orders/2');

    expect(collect(signals())->pluck('status')->all())->toBe([404, 404])
        ->and(collect(signals())->pluck('path')->all())->toBe(['orders/1', 'orders/2'])
        ->and(collect(signals())->pluck('detector')->unique()->all())->toBe(['response_bursts']);
});

it('logs the account a failed login aimed at, apart from the user on the request', function () {
    $target = new User;
    $target->id = 42;

    Route::post('/login', function () use ($target) {
        event(new Failed('web', $target, ['email' => ' Alice@Example.com', 'password' => 'hunter2-secret']));

        return 'tried';
    });

    $this->withServerVariables(['REMOTE_ADDR' => '203.0.113.5'])->post('/login');

    $row = signals()[0];

    expect($row)->toMatchArray([
        'detector'       => 'failed_logins',
        'user_id'        => null,
        'target_user_id' => '42',
        'guard'          => 'web',
        'path'           => 'login',
        'target_hash'    => SignalLog::targetHash(['email' => 'alice@example.com']),
    ])
        ->and($row['target_hash'])->toHaveLength(64)
        ->and(implode('|', array_map(strval(...), $row)))->not->toContain('hunter2');
});

it('logs a failed login at an account that does not exist, by hash alone', function () {
    Route::post('/login', function () {
        event(new Failed('web', null, ['email' => 'nobody@example.com', 'password' => 'x']));

        return 'tried';
    });

    $this->withServerVariables(['REMOTE_ADDR' => '203.0.113.6'])->post('/login');

    expect(signals()[0]['target_user_id'])->toBeNull()
        ->and(signals()[0]['target_hash'])->toBe(SignalLog::targetHash(['email' => 'nobody@example.com']));
});

it('hashes one identifier the same whatever its case, spacing or password', function () {
    $hash = SignalLog::targetHash(['email' => 'alice@example.com', 'password' => 'a']);

    expect(SignalLog::targetHash(['email' => ' ALICE@example.com ', 'password' => 'b']))->toBe($hash)
        // Laravel's own rule for which keys identify a user: none containing "password".
        ->and(SignalLog::targetHash(['email' => 'alice@example.com', 'current_password' => 'c', 'password_confirmation' => 'd']))->toBe($hash)
        // Invalid UTF-8 must not collapse every such identifier into one hash.
        ->and(SignalLog::targetHash(['email' => "a\xFF@example.com"]))->not->toBe(SignalLog::targetHash(['email' => "b\xFF@example.com"]))
        ->and(SignalLog::targetHash(['email' => 'bob@example.com']))->not->toBe($hash)
        ->and(SignalLog::targetHash(['password' => 'only']))->toBeNull()
        ->and(SignalLog::targetHash([]))->toBeNull();

    // Keyed: the hash is useless without the app key.
    config()->set('app.key', 'base64:'.base64_encode(random_bytes(32)));

    expect(SignalLog::targetHash(['email' => 'alice@example.com']))->not->toBe($hash);
});

it('writes nothing for an address already blocked app-wide', function () {
    // Called directly: over HTTP, BlockedIpMiddleware turns a blocked
    // address away before any detector runs, so detect()'s own check would
    // never be reached.
    app(BlacklistService::class)->block('203.0.113.7');

    // Both ways detect() learns it: the verdict the middleware passes, and
    // its own lookup when there is none.
    app(AutoBlockService::class)->record('scanner_paths', '203.0.113.7', null, true, ['path' => '.env']);
    app(AutoBlockService::class)->record('scanner_paths', '203.0.113.7', null, null, ['path' => '.env']);
    app()->terminate();

    expect(signals())->toBe([]);
});

it('writes nothing for an address already blocked where a scoped detector aims, and logs the rest', function () {
    config()->set('watchtower.auto_block.detectors.scanner_paths.scope', 'auth');
    app(BlacklistService::class)->block('203.0.113.30', ['scope' => 'auth']);

    app(AutoBlockService::class)->record('scanner_paths', '203.0.113.30', null, false, ['path' => '.env']);
    app(AutoBlockService::class)->record('scanner_paths', '203.0.113.31', null, false, ['path' => '.env']);
    app()->terminate();

    expect(collect(signals())->pluck('ip')->all())->toBe(['203.0.113.31']);
});

it('logs a login lockout', function () {
    Route::post('/login', function (Request $request) {
        event(new Lockout($request));

        return 'locked';
    });

    $this->withServerVariables(['REMOTE_ADDR' => '203.0.113.32'])->post('/login');

    expect(signals('login_lockouts'))->toHaveCount(1)
        ->and(signals('login_lockouts')[0])->toMatchArray([
            'ip'          => '203.0.113.32',
            'path'        => 'login',
            'user_id'     => null,
            'target_hash' => null,
        ]);
});

it('stores an IPv6 address as it came in, not widened to its block target', function () {
    $this->withServerVariables(['REMOTE_ADDR' => '2001:db8::1'])->get('/.env');

    expect(signals('scanner_paths')[0]['ip'])->toBe('2001:db8::1');
});

it('stores a path with invalid UTF-8 or a NUL byte as text a database accepts', function () {
    app(AutoBlockService::class)->record('scanner_paths', '203.0.113.33', null, false, ['path' => ".env\xFF\x00x"]);
    app()->terminate();

    $path = signals()[0]['path'];

    expect(mb_check_encoding($path, 'UTF-8'))->toBeTrue()
        ->and($path)->not->toContain("\0")
        ->and($path)->toStartWith('.env');
});

it('writes nothing for a detector that is switched off', function () {
    config()->set('watchtower.auto_block.detectors.scanner_paths.enabled', false);

    $this->withServerVariables(['REMOTE_ADDR' => '203.0.113.8'])->get('/.env');

    expect(signals('scanner_paths'))->toBe([])
        ->and(signals('response_bursts'))->toHaveCount(1);
});

it('holds rows until the app terminates', function () {
    app(AutoBlockService::class)->record('scanner_paths', '203.0.113.9', null, false, ['path' => '.env']);

    expect(signals())->toBe([]);

    app()->terminate();

    expect(signals())->toHaveCount(1);

    // Flushed means emptied: a second terminate writes nothing again.
    app()->terminate();

    expect(signals())->toHaveCount(1);
});

it('drops the rows and keeps the request and the block when the table is missing', function () {
    config()->set('watchtower.auto_block.mode', 'block');
    Schema::drop(SignalLog::TABLE);

    $warnings = [];
    $channel = Mockery::mock();
    $channel->shouldReceive('warning')->andReturnUsing(function ($message) use (&$warnings) {
        $warnings[] = $message;
    });
    $channel->shouldReceive('info', 'error', 'debug', 'notice');
    Log::shouldReceive('channel')->andReturn($channel);

    $this->withServerVariables(['REMOTE_ADDR' => '203.0.113.10'])->get('/.env')->assertForbidden();
    $this->withServerVariables(['REMOTE_ADDR' => '203.0.113.11'])->get('/.git/config')->assertForbidden();

    $this->assertDatabaseHas('blacklisted_ips', ['ip' => '203.0.113.10']);

    // Once, not once per request: the second failure falls in the window.
    expect(array_values(array_filter($warnings, fn ($m) => str_contains($m, 'could not write the signal log'))))
        ->toBe(['Watchtower: could not write the signal log, dropping 1 signal(s)']);
});

describe('watchtower:cleanup', function () {
    function signalRow(string $ip, DateTimeInterface $at): array
    {
        return ['detector' => 'scanner_paths', 'ip' => $ip, 'occurred_at' => $at];
    }

    it('drops rows past retention_days and keeps the rest, with the log switched off', function () {
        config()->set('watchtower.auto_block.signal_log.enabled', false);
        // Not the default, so a hardcoded 14 can't pass.
        config()->set('watchtower.auto_block.signal_log.retention_days', 3);
        $this->freezeTime();

        DB::table(SignalLog::TABLE)->insert([
            signalRow('203.0.113.20', now()->subDays(3)->subMinute()),
            signalRow('203.0.113.21', now()->subDays(3)->addMinute()),
        ]);

        $this->artisan('watchtower:cleanup')
            ->assertSuccessful()
            ->expectsOutputToContain('Dropped 1 signal log row(s) older than 3 days.');

        expect(collect(signals())->pluck('ip')->all())->toBe(['203.0.113.21']);
    });

    it('drops more rows than one batch holds', function () {
        DB::table(SignalLog::TABLE)->insert(
            array_map(fn () => signalRow('203.0.113.22', now()->subDays(30)), range(1, 1001)),
        );

        $this->artisan('watchtower:cleanup')
            ->assertSuccessful()
            ->expectsOutputToContain('Dropped 1001 signal log row(s)');

        expect(signals())->toBe([]);
    });

    it('carries on without the table', function () {
        Schema::drop(SignalLog::TABLE);

        $this->artisan('watchtower:cleanup')
            ->assertSuccessful()
            ->doesntExpectOutputToContain('signal log');
    });
});
