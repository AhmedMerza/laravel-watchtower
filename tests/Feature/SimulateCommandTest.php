<?php

declare(strict_types=1);

use Illuminate\Auth\Events\Failed;
use Illuminate\Auth\Events\Lockout;
use Illuminate\Http\Request;
use Illuminate\Log\Events\MessageLogged;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Schema;
use Illuminate\Support\Str;
use Watchtower\Listeners\DetectAuthFailures;
use Watchtower\Services\AutoBlockService;

beforeEach(function () {
    Carbon::setTestNow('2026-09-21 12:00:00');

    config()->set('cache.default', 'array');
    config()->set('watchtower.cache.store', 'array');
    config()->set('watchtower.auto_block.block_duration_minutes', 60);
    config()->set('watchtower.auto_block.shared_ip_user_threshold', 3);
});

afterEach(function () {
    Carbon::setTestNow();
});

/** A burst of $count entries from $ip, one per second, ending $minutesAgo ago. */
function seedBurst(string $ip, int $count, int $minutesAgo, array $attributes = []): void
{
    $start = now()->copy()->subMinutes($minutesAgo);

    for ($i = 0; $i < $count; $i++) {
        logEntry($ip, array_merge(['occurred_at' => $start->copy()->addSeconds($i)], $attributes));
    }
}

function oneRule(array $overrides = []): void
{
    config()->set('watchtower.auto_block.rules', [array_merge([
        'level'          => 'error',
        'count'          => 10,
        'window_minutes' => 5,
    ], $overrides)]);
}

it('names the addresses a rule would have blocked', function () {
    seedBurst('10.0.0.1', 10, 30);
    oneRule();

    $this->artisan('watchtower:simulate')
        ->assertSuccessful()
        ->expectsOutputToContain('10.0.0.1');
});

it('says plainly when a rule would have blocked nothing', function () {
    seedBurst('10.0.0.1', 3, 30);
    oneRule();

    $this->artisan('watchtower:simulate')
        ->assertSuccessful()
        ->expectsOutputToContain('Nothing would have been blocked.');
});

it('writes nothing at all, enforced by the database', function () {
    seedBurst('10.0.0.1', 30, 30, ['user_id' => 5]);
    oneRule();

    // Every INSERT, UPDATE and DELETE on the package's tables — and on the
    // log table it reads — now aborts. A single write anywhere in the
    // command turns this into a QueryException rather than a silent pass.
    failAllWatchtowerWrites();

    $this->artisan('watchtower:simulate')->assertSuccessful();

    expect(DB::table('blacklisted_ips')->count())->toBe(0);
});

it('writes nothing even when the rule is armed to block', function () {
    // The dangerous case: config says `block`, so anything that reached the
    // real engine would blacklist these addresses for an hour.
    config()->set('watchtower.auto_block.enabled', true);
    config()->set('watchtower.auto_block.mode', 'block');

    seedBurst('10.0.0.1', 30, 30);
    oneRule(['mode' => 'block']);

    failAllWatchtowerWrites();

    $this->artisan('watchtower:simulate')->assertSuccessful();

    expect(DB::table('blacklisted_ips')->count())->toBe(0);
});

it('reports regardless of whether the engine is switched on', function () {
    // The whole point is deciding whether to switch it on, so a disabled
    // engine must not produce an empty report.
    config()->set('watchtower.auto_block.enabled', false);

    seedBurst('10.0.0.1', 10, 30);
    oneRule();

    $this->artisan('watchtower:simulate')
        ->assertSuccessful()
        ->expectsOutputToContain('10.0.0.1');
});

it('emits json with --json', function () {
    seedBurst('10.0.0.1', 10, 30, ['user_id' => 9]);
    oneRule();

    // Artisan::call() rather than $this->artisan(), which buffers its output
    // somewhere Artisan::output() can't see.
    $exit = Artisan::call('watchtower:simulate', ['--json' => true, '--days' => '7']);

    expect($exit)->toBe(0);

    $decoded = json_decode(Artisan::output(), true, flags: JSON_THROW_ON_ERROR);

    expect($decoded['days'])->toBe(7)
        ->and($decoded['table'])->toBe('log_entries')
        ->and($decoded['rules'][0]['offenders'][0])
        ->toMatchArray(['ip' => '10.0.0.1', 'blocks' => 1, 'warnings' => 0, 'distinct_users' => 1, 'downgraded_to_scope' => null]);
});

it('narrows to one rule with --rule', function () {
    seedBurst('10.0.0.1', 10, 30, ['level' => 'error']);
    seedBurst('10.0.0.2', 10, 30, ['level' => 'warning']);

    config()->set('watchtower.auto_block.rules', [
        ['level' => 'error', 'count' => 10, 'window_minutes' => 5],
        ['level' => 'warning', 'count' => 10, 'window_minutes' => 5],
    ]);

    $exit = Artisan::call('watchtower:simulate', ['--rule' => '1', '--json' => true]);

    expect($exit)->toBe(0);

    $decoded = json_decode(Artisan::output(), true, flags: JSON_THROW_ON_ERROR);

    expect($decoded['rules'])->toHaveCount(1)
        ->and($decoded['rules'][0]['rule_index'])->toBe(1)
        ->and($decoded['rules'][0]['offenders'][0]['ip'])->toBe('10.0.0.2');
});

it('refuses a --rule that names no configured rule', function () {
    oneRule();

    $this->artisan('watchtower:simulate --rule=7')
        ->assertFailed()
        ->expectsOutputToContain('--rule must be the index of a configured rule.');
});

it('refuses a --days that is not a positive whole number', function () {
    oneRule();

    $this->artisan('watchtower:simulate --days=0')->assertFailed();
    $this->artisan('watchtower:simulate --days=-3')->assertFailed();
    $this->artisan('watchtower:simulate --days=lots')->assertFailed();
});

it('succeeds quietly when no rules or detectors are configured', function () {
    config()->set('watchtower.auto_block.rules', []);

    // Not a failure: a scripted caller shouldn't treat an app with
    // auto-block switched off as broken.
    $this->artisan('watchtower:simulate')
        ->assertSuccessful()
        ->expectsOutputToContain('No auto-block rules or detectors are configured');
});

it('explains itself when the log table is missing', function () {
    Schema::drop('log_entries');
    oneRule();

    $this->artisan('watchtower:simulate')
        ->assertFailed()
        ->expectsOutputToContain("The log table `log_entries` doesn't exist");
});

it('warns about signed-in traffic a block would have taken down with it', function () {
    seedBurst('10.0.0.1', 10, 30, ['level' => 'error']);
    logEntry('10.0.0.1', ['level' => 'info', 'user_id' => 42, 'occurred_at' => now()->copy()->subMinutes(20)]);

    oneRule();

    $this->artisan('watchtower:simulate')
        ->assertSuccessful()
        ->expectsOutputToContain('also sent signed-in traffic that never matched the rule');
});

it('warns when the shared-IP guard would have held a block back', function () {
    seedBurst('10.0.0.1', 10, 30);

    foreach ([1, 2, 3] as $i => $userId) {
        logEntry('10.0.0.1', [
            'user_id'     => $userId,
            'occurred_at' => now()->copy()->subMinutes(30)->addSeconds($i),
        ]);
    }

    oneRule();

    $this->artisan('watchtower:simulate')
        ->assertSuccessful()
        // Held back at every tick until the users and the burst age out
        // together, so the address is listed for its warnings but not
        // counted as blocked.
        ->expectsOutputToContain('0 address(es) would have been blocked, 0 block(s) in total.')
        ->expectsOutputToContain('5 held back')
        ->expectsOutputToContain('1 would have been held back by the shared-IP guard (>= 3 signed-in users): 5 warning(s)');
});

it('honours a custom logscope table name', function () {
    Schema::create('custom_logs', function ($table) {
        $table->string('id', 26)->primary();
        $table->string('level', 20);
        $table->text('message');
        $table->string('ip_address', 50)->nullable();
        $table->unsignedBigInteger('user_id')->nullable();
        $table->dateTime('occurred_at');
        $table->dateTime('created_at')->nullable();
        $table->dateTime('updated_at')->nullable();
    });

    config()->set('logscope.table', 'custom_logs');

    for ($i = 0; $i < 10; $i++) {
        DB::table('custom_logs')->insert([
            'id'          => (string) Str::ulid(),
            'level'       => 'error',
            'message'     => 'Boom',
            'ip_address'  => '10.9.9.9',
            'occurred_at' => now()->copy()->subMinutes(30)->addSeconds($i),
        ]);
    }

    oneRule();

    $this->artisan('watchtower:simulate')
        ->assertSuccessful()
        ->expectsOutputToContain('10.9.9.9');
});

it('does not crash when the global auto_block mode is literally null', function () {
    // WATCHTOWER_AUTO_BLOCK_MODE=null in .env gives the key a real PHP null,
    // and config()'s default only covers an ABSENT key — so this used to
    // hand null to a `string $mode` parameter and fatal under strict_types.
    config()->set('watchtower.auto_block.mode', null);

    seedBurst('10.0.0.1', 10, 30);
    oneRule();

    $this->artisan('watchtower:simulate')
        ->assertSuccessful()
        ->expectsOutputToContain('10.0.0.1');
});

it('refuses a --days beyond the ten-year ceiling', function () {
    // Carbon happily returns a date in the year -2735881 for this, which
    // would make every row "inside" the period and turn the narrowing
    // aggregate into a whole-table scan.
    oneRule();

    $this->artisan('watchtower:simulate --days=999999999')->assertFailed();
    $this->artisan('watchtower:simulate --days=3650')->assertSuccessful();
});

it('says a rule is skipped when its scope is not declared', function () {
    config()->set('watchtower.scopes', ['auth']);

    seedBurst('10.0.0.1', 20, 30);
    oneRule(['scope' => 'nonsense', 'count' => 5]);

    $this->artisan('watchtower:simulate')
        ->assertSuccessful()
        ->expectsOutputToContain('is not declared in watchtower.scopes')
        ->doesntExpectOutputToContain('10.0.0.1');
});

it('names the addresses an allow-list protects instead of listing them as blocks', function () {
    config()->set('watchtower.never_block', ['10.0.0.1']);

    seedBurst('10.0.0.1', 20, 30);
    oneRule(['count' => 5]);

    $this->artisan('watchtower:simulate')
        ->assertSuccessful()
        ->expectsOutputToContain('never_block / never_auto_block');
});

it('reports a scoped downgrade as a block in scope, not as a warning', function () {
    config()->set('watchtower.scopes', ['auth']);

    seedBurst('10.0.0.1', 10, 30);

    foreach ([1, 2, 3] as $i => $userId) {
        logEntry('10.0.0.1', [
            'user_id'     => $userId,
            'occurred_at' => now()->copy()->subMinutes(30)->addSeconds($i),
        ]);
    }

    oneRule(['scope' => 'auth']);

    $this->artisan('watchtower:simulate')
        ->assertSuccessful()
        ->expectsOutputToContain('blocked them in scope rather than app-wide')
        ->doesntExpectOutputToContain('would have been warnings, not blocks');
});

it('judges a rule by its own user threshold, and says which (#121)', function () {
    seedBurst('10.0.0.9', 10, 30, ['user_id' => 7]);

    oneRule(['shared_ip_user_threshold' => 1]);

    $this->artisan('watchtower:simulate')
        ->assertSuccessful()
        ->expectsOutputToContain('0 address(es) would have been blocked')
        ->expectsOutputToContain('held back by the shared-IP guard (>= 1 signed-in users)');
});

it('reports each rule\'s user threshold in --json', function () {
    config()->set('watchtower.auto_block.rules', [
        ['level' => 'error', 'count' => 10, 'window_minutes' => 5, 'shared_ip_user_threshold' => 1],
        ['level' => 'error', 'count' => 10, 'window_minutes' => 5],
    ]);

    expect(Artisan::call('watchtower:simulate', ['--json' => true]))->toBe(0);

    $json = json_decode(Artisan::output(), true, flags: JSON_THROW_ON_ERROR);

    expect(array_column($json['rules'], 'shared_ip_user_threshold'))->toBe([1, 3]);
});

/**
 * A would-have-blocked line as the live engine writes it, $minutesAgo ago.
 * The context shape is AutoBlockService::detect()'s plus logWouldHaveBlocked().
 */
function wouldHaveBlocked(string $ip, string $detector, int $minutesAgo, array $context = []): void
{
    logEntry($ip, [
        'level'       => 'warning',
        'message'     => AutoBlockService::WOULD_HAVE_BLOCKED_MESSAGE,
        'occurred_at' => now()->subMinutes($minutesAgo),
        'context'     => json_encode(array_merge([
            'would_have_blocked'  => true,
            'ip'                  => $ip,
            'detector'            => $detector,
            'user_ids'            => [],
            'not_blocked_because' => 'warn mode',
            'in_block_mode'       => 'blocked',
        ], $context)),
    ]);
}

function onlyDetector(string $name, array $overrides = []): void
{
    config()->set('watchtower.auto_block.enabled', true);
    config()->set('watchtower.auto_block.rules', []);
    config()->set("watchtower.auto_block.detectors.{$name}", array_merge(['enabled' => true, 'mode' => 'warn'], $overrides));
}

it('reports what a detector saw in warn mode instead of saying there is nothing to backtest (#123)', function () {
    onlyDetector('response_bursts');
    wouldHaveBlocked('10.0.0.9', 'response_bursts', 120);
    wouldHaveBlocked('10.0.0.9', 'response_bursts', 30);

    $this->artisan('watchtower:simulate')
        ->assertSuccessful()
        ->expectsOutputToContain('observed, not simulated')
        ->expectsOutputToContain('Detector response_bursts [warn]')
        ->expectsTable(
            ['IP', 'Reports', 'First', 'Last', 'Signed-in users', 'In block mode'],
            [['10.0.0.9', 2, '2026-09-21 10:00', '2026-09-21 11:30', 0, 'blocked']],
        )
        ->doesntExpectOutputToContain('nothing to backtest');
});

it('warns when block mode would have locked signed-in users out', function () {
    onlyDetector('response_bursts');
    wouldHaveBlocked('10.0.0.9', 'response_bursts', 30, ['user_ids' => [7]]);
    // Held back by the guard in block mode too: not a lock-out, not counted.
    wouldHaveBlocked('10.0.0.8', 'response_bursts', 30, ['user_ids' => [8, 9, 10], 'in_block_mode' => 'shared IP']);

    $this->artisan('watchtower:simulate')
        ->assertSuccessful()
        ->expectsOutputToContain('1 of these had signed-in users and block mode would have blocked them app-wide');
});

it('does not guess what block mode would do from a line that predates in_block_mode', function () {
    // An install upgraded from v0.6.1 has history with no
    // in_block_mode at all. Reading that as 'blocked' would be invented.
    onlyDetector('response_bursts');
    wouldHaveBlocked('10.0.0.9', 'response_bursts', 30, ['user_ids' => [7], 'in_block_mode' => null]);

    $this->artisan('watchtower:simulate')
        ->assertSuccessful()
        ->expectsTable(
            ['IP', 'Reports', 'First', 'Last', 'Signed-in users', 'In block mode'],
            [['10.0.0.9', 1, '2026-09-21 11:30', '2026-09-21 11:30', 1, 'not recorded']],
        )
        ->expectsOutputToContain('1 of these had signed-in users, reported before v0.11.0')
        ->doesntExpectOutputToContain('would have blocked them app-wide');
});

it('leaves rule near-misses and old or unrelated lines out of the detector report', function () {
    onlyDetector('scanner_paths');
    wouldHaveBlocked('10.0.0.1', 'scanner_paths', 30);
    wouldHaveBlocked('10.0.0.2', 'scanner_paths', 8 * 24 * 60);             // before --days=7
    logEntry('10.0.0.3', [                                                  // a rule's near miss
        'level'   => 'warning',
        'message' => AutoBlockService::WOULD_HAVE_BLOCKED_MESSAGE,
        'context' => json_encode(['would_have_blocked' => true, 'ip' => '10.0.0.3', 'rule' => 0]),
    ]);
    logEntry('10.0.0.4', ['level' => 'warning', 'context' => json_encode(['detector' => 'scanner_paths', 'ip' => '10.0.0.4'])]);

    expect(Artisan::call('watchtower:simulate', ['--json' => true]))->toBe(0);

    $json = json_decode(Artisan::output(), true, flags: JSON_THROW_ON_ERROR);

    expect(array_column($json['detectors']['scanner_paths']['offenders'], 'ip'))->toBe(['10.0.0.1']);
});

it('counts a truncated context instead of dropping it silently', function () {
    onlyDetector('failed_logins');
    logEntry('10.0.0.5', [
        'level'   => 'warning',
        'message' => AutoBlockService::WOULD_HAVE_BLOCKED_MESSAGE,
        'context' => '{"would_have_blocked":true,"ip":"10.0.0.5","detec',
    ]);

    $this->artisan('watchtower:simulate')
        ->assertSuccessful()
        ->expectsOutputToContain('1 would-have-blocked or auto-blocked line(s) could not be used');
});

it('says why an enabled detector has no history', function () {
    onlyDetector('failed_logins');

    $this->artisan('watchtower:simulate')
        ->assertSuccessful()
        ->expectsOutputToContain('Either it never reached its threshold');

    config()->set('watchtower.auto_block.enabled', false);

    $this->artisan('watchtower:simulate')
        ->assertSuccessful()
        ->expectsOutputToContain('auto_block.enabled is off');
});

it('still reports a detector switched off since, from its history', function () {
    onlyDetector('bad_user_agent', ['enabled' => false]);
    wouldHaveBlocked('10.0.0.6', 'bad_user_agent', 30);

    $this->artisan('watchtower:simulate')
        ->assertSuccessful()
        ->expectsOutputToContain('Detector bad_user_agent [warn] — switched off now');
});

it('skips the detectors when --rule narrows to one rule', function () {
    onlyDetector('response_bursts');
    wouldHaveBlocked('10.0.0.9', 'response_bursts', 30);
    seedBurst('10.0.0.1', 10, 30);
    oneRule();

    $this->artisan('watchtower:simulate', ['--rule' => '0'])
        ->assertSuccessful()
        ->doesntExpectOutputToContain('Detector response_bursts');
});

it('writes nothing while reading detector history, enforced by the database', function () {
    onlyDetector('response_bursts');
    wouldHaveBlocked('10.0.0.9', 'response_bursts', 30);
    failAllWatchtowerWrites();

    $this->artisan('watchtower:simulate')->assertSuccessful();
});

it('reads back the line the live detector actually writes, not just a hand-built one', function (string $detector, Closure $fire) {
    // The helper above writes the context shape by hand, so a rename on the
    // engine side would leave every test above green. This drives the real
    // listener and stores its line the way LogScope does — on MessageLogged.
    onlyDetector($detector, ['count' => 2, 'window_minutes' => 5]);

    Event::listen(MessageLogged::class, function (MessageLogged $log): void {
        if ($log->message === AutoBlockService::WOULD_HAVE_BLOCKED_MESSAGE) {
            logEntry($log->context['ip'], [
                'level'   => $log->level,
                'message' => $log->message,
                'context' => json_encode($log->context),
            ]);
        }
    });

    // The listener records no user; the user is a LogScope row.
    logEntry('10.0.0.7', ['user_id' => 7, 'occurred_at' => now()->subHour()]);

    $request = Request::create('/login', 'POST', server: ['REMOTE_ADDR' => '10.0.0.7']);
    app()->instance('request', $request);
    $listener = app(DetectAuthFailures::class);
    $fire($listener, $request);
    $fire($listener, $request);

    $this->artisan('watchtower:simulate')
        ->assertSuccessful()
        ->expectsTable(
            ['IP', 'Reports', 'First', 'Last', 'Users seen at IP', 'In block mode'],
            [['10.0.0.7', 1, '2026-09-21 12:00', '2026-09-21 12:00', 1, 'blocked']],
        )
        ->expectsOutputToContain('1 of these had signed-in users');
})->with([
    'failed_logins'  => ['failed_logins', fn (DetectAuthFailures $l) => $l->handleFailed(new Failed('web', null, []))],
    'login_lockouts' => ['login_lockouts', fn (DetectAuthFailures $l, Request $r) => $l->handleLockout(new Lockout($r))],
]);

it('counts who LogScope saw at an auth detector\'s address, since its lines name no one (#141)', function (string $detector) {
    onlyDetector($detector);
    wouldHaveBlocked('10.0.0.9', $detector, 30);
    wouldHaveBlocked('10.0.0.8', $detector, 30);
    // Two customers behind 10.0.0.9, one of them twice; one only before the
    // window and one after it.
    logEntry('10.0.0.9', ['user_id' => 7, 'occurred_at' => now()->subDays(2)]);
    logEntry('10.0.0.9', ['user_id' => 7, 'occurred_at' => now()->subDay()]);
    logEntry('10.0.0.9', ['user_id' => 8, 'occurred_at' => now()->subHour()]);
    logEntry('10.0.0.9', ['user_id' => 9, 'occurred_at' => now()->subDays(8)]);
    logEntry('10.0.0.9', ['user_id' => 11, 'occurred_at' => now()->addMinute()]);
    logEntry('10.0.0.6', ['user_id' => 10, 'occurred_at' => now()->subHour()]);

    $this->artisan('watchtower:simulate')
        ->assertSuccessful()
        ->expectsTable(
            ['IP', 'Reports', 'First', 'Last', 'Users seen at IP', 'In block mode'],
            [
                ['10.0.0.8', 1, '2026-09-21 11:30', '2026-09-21 11:30', 0, 'blocked'],
                ['10.0.0.9', 1, '2026-09-21 11:30', '2026-09-21 11:30', 2, 'blocked'],
            ],
        )
        ->expectsOutputToContain('the shared-IP guard')
        ->expectsOutputToContain('never_auto_block before arming it')
        ->expectsOutputToContain('1 of these had signed-in users and block mode would have blocked them app-wide');

    expect(Artisan::call('watchtower:simulate', ['--json' => true]))->toBe(0);
    $json = json_decode(Artisan::output(), true, flags: JSON_THROW_ON_ERROR);

    expect(array_column($json['detectors'][$detector]['offenders'], 'logscope_users', 'ip'))
        ->toBe(['10.0.0.8' => 0, '10.0.0.9' => 2]);
})->with(AutoBlockService::USERLESS_DETECTORS);

it('uses the LogScope count for an auth detector\'s scoped and unrecorded warnings too', function () {
    onlyDetector('failed_logins');
    wouldHaveBlocked('10.0.0.9', 'failed_logins', 30, ['in_block_mode' => 'blocked_in_scope']);
    wouldHaveBlocked('10.0.0.8', 'failed_logins', 30, ['in_block_mode' => null]);
    logEntry('10.0.0.9', ['user_id' => 7, 'occurred_at' => now()->subHour()]);
    logEntry('10.0.0.8', ['user_id' => 8, 'occurred_at' => now()->subHour()]);

    $this->artisan('watchtower:simulate')
        ->assertSuccessful()
        ->expectsOutputToContain('1 more had signed-in users and would have been blocked in the detector\'s scope')
        ->expectsOutputToContain('1 of these had signed-in users, reported before v0.11.0');
});

it('keeps the line\'s own users for detectors that see them', function () {
    onlyDetector('response_bursts');
    wouldHaveBlocked('10.0.0.9', 'response_bursts', 30);
    logEntry('10.0.0.9', ['user_id' => 7, 'occurred_at' => now()->subHour()]);

    $this->artisan('watchtower:simulate')
        ->assertSuccessful()
        ->expectsTable(
            ['IP', 'Reports', 'First', 'Last', 'Signed-in users', 'In block mode'],
            [['10.0.0.9', 1, '2026-09-21 11:30', '2026-09-21 11:30', 0, 'blocked']],
        )
        ->doesntExpectOutputToContain('Users seen at IP');
});

it('merges an address\'s reports: users, first and last, and each outcome', function () {
    onlyDetector('response_bursts');
    // Newest inserted first, so id order is not time order.
    wouldHaveBlocked('10.0.0.9', 'response_bursts', 30, ['user_ids' => [7, 8]]);
    wouldHaveBlocked('10.0.0.9', 'response_bursts', 120, ['user_ids' => [8, 9]]);
    wouldHaveBlocked('10.0.0.9', 'response_bursts', 60, ['in_block_mode' => 'shared IP']);

    $this->artisan('watchtower:simulate')
        ->assertSuccessful()
        ->expectsTable(
            ['IP', 'Reports', 'First', 'Last', 'Signed-in users', 'In block mode'],
            [['10.0.0.9', 3, '2026-09-21 10:00', '2026-09-21 11:30', 3, 'blocked ×2, shared IP ×1']],
        )
        ->expectsOutputToContain('1 of these had signed-in users and block mode would have blocked them app-wide');
});

it('reports block mode\'s own hold-backs as held, not as lock-outs', function () {
    onlyDetector('response_bursts', ['mode' => 'block']);
    wouldHaveBlocked('10.0.0.9', 'response_bursts', 30, ['user_ids' => [7, 8, 9], 'not_blocked_because' => 'shared IP']);
    wouldHaveBlocked('10.0.0.8', 'response_bursts', 30, ['user_ids' => [7], 'not_blocked_because' => null]);

    $this->artisan('watchtower:simulate')
        ->assertSuccessful()
        ->expectsTable(
            ['IP', 'Reports', 'First', 'Last', 'Signed-in users', 'In block mode'],
            [
                ['10.0.0.8', 1, '2026-09-21 11:30', '2026-09-21 11:30', 1, 'held: unknown'],
                ['10.0.0.9', 1, '2026-09-21 11:30', '2026-09-21 11:30', 3, 'held: shared IP'],
            ],
        )
        ->doesntExpectOutputToContain('locked those people out');
});

it('says a scoped block would have left signed-in users the rest of the app', function () {
    onlyDetector('response_bursts');
    wouldHaveBlocked('10.0.0.9', 'response_bursts', 30, ['user_ids' => [7], 'in_block_mode' => 'blocked_in_scope']);

    $this->artisan('watchtower:simulate')
        ->assertSuccessful()
        ->expectsOutputToContain('1 more had signed-in users and would have been blocked in the detector\'s scope')
        ->doesntExpectOutputToContain('locked those people out');
});

it('says a scoped detector would have blocked signed-in users on its routes, not app-wide (#151)', function () {
    config()->set('watchtower.scopes', ['auth']);
    onlyDetector('failed_logins', ['scope' => 'auth']);
    wouldHaveBlocked('10.0.0.9', 'failed_logins', 30);
    wouldHaveBlocked('10.0.0.8', 'failed_logins', 30, ['in_block_mode' => 'blocked_in_scope']);
    logEntry('10.0.0.9', ['user_id' => 7, 'occurred_at' => now()->subHour()]);
    logEntry('10.0.0.8', ['user_id' => 8, 'occurred_at' => now()->subHour()]);

    $this->artisan('watchtower:simulate')
        ->assertSuccessful()
        ->expectsOutputToContain("2 of these had signed-in users and block mode would have blocked them on 'auth' routes only")
        ->doesntExpectOutputToContain('app-wide')
        ->doesntExpectOutputToContain('1 more had signed-in users');
});

function autoBlocked(string $ip, string $detector, int $minutesAgo, array $context = []): void
{
    logEntry($ip, [
        'level'       => 'warning',
        'message'     => AutoBlockService::AUTO_BLOCKED_MESSAGE,
        'occurred_at' => now()->subMinutes($minutesAgo),
        'context'     => json_encode(array_merge([
            'auto_blocked'     => true,
            'ip'               => $ip,
            'detector'         => $detector,
            'user_ids'         => [],
            'target'           => $ip,
            'scope'            => '',
            'duration_minutes' => 1,
            'expires_at'       => now()->subMinutes($minutesAgo - 1)->toIso8601String(),
        ], $context)),
    ]);
}

it('lists the blocks a detector really wrote next to its near misses (#154)', function () {
    config()->set('watchtower.scopes', ['auth']);
    onlyDetector('failed_logins', ['mode' => 'block', 'scope' => 'auth']);
    autoBlocked('10.0.0.9', 'failed_logins', 120, ['scope' => 'auth', 'duration_minutes' => 1]);
    autoBlocked('10.0.0.9', 'failed_logins', 30, ['scope' => 'auth', 'duration_minutes' => 15]);
    autoBlocked('10.0.0.8', 'failed_logins', 60, ['scope' => 'auth', 'expires_at' => 'not a time']);
    // A rule's real block is RuleSimulator's business, not a detector's.
    logEntry('10.0.0.7', [
        'level'       => 'warning',
        'message'     => AutoBlockService::AUTO_BLOCKED_MESSAGE,
        'occurred_at' => now()->subMinutes(10),
        'context'     => json_encode(['auto_blocked' => true, 'ip' => '10.0.0.7', 'rule' => 'x', 'duration_minutes' => 5]),
    ]);
    wouldHaveBlocked('10.0.0.6', 'failed_logins', 30, ['not_blocked_because' => 'never_auto_block']);

    $this->artisan('watchtower:simulate')
        ->assertSuccessful()
        ->expectsOutputToContain('3 real block(s) on 2 address(es):')
        ->expectsTable(
            ['IP', 'Blocks', 'First', 'Last', 'Minutes', 'Scope', 'Last expires'],
            [
                ['10.0.0.9', 2, '2026-09-21 10:00', '2026-09-21 11:30', 16, 'auth', '2026-09-21 11:31'],
                ['10.0.0.8', 1, '2026-09-21 11:00', '2026-09-21 11:00', 1, 'auth', '?'],
            ],
        )
        ->expectsTable(
            ['IP', 'Reports', 'First', 'Last', 'Users seen at IP', 'In block mode'],
            [['10.0.0.6', 1, '2026-09-21 11:30', '2026-09-21 11:30', 0, 'held: never_auto_block']],
        )
        ->doesntExpectOutputToContain('10.0.0.7')
        ->doesntExpectOutputToContain('could not be used');

    expect(Artisan::call('watchtower:simulate', ['--json' => true]))->toBe(0);
    $json = json_decode(Artisan::output(), true, flags: JSON_THROW_ON_ERROR);

    expect($json['detectors']['failed_logins']['blocks'][0])->toMatchArray([
        'ip'      => '10.0.0.9',
        'blocks'  => 2,
        'minutes' => 16,
        'scopes'  => ['auth'],
    ]);
});

it('reports a detector that only really blocked, without explaining an empty history (#154)', function () {
    onlyDetector('scanner_paths', ['mode' => 'block']);
    autoBlocked('10.0.0.9', 'scanner_paths', 30);

    $this->artisan('watchtower:simulate')
        ->assertSuccessful()
        ->expectsOutputToContain('1 real block(s) on 1 address(es):')
        ->expectsTable(
            ['IP', 'Blocks', 'First', 'Last', 'Minutes', 'Scope', 'Last expires'],
            [['10.0.0.9', 1, '2026-09-21 11:30', '2026-09-21 11:30', 1, 'app-wide', '2026-09-21 11:31']],
        )
        ->expectsOutputToContain('No would-have-blocked reports.')
        ->doesntExpectOutputToContain('No real block was logged either');
});

it('explains an empty history in block mode and in disabled mode', function () {
    onlyDetector('failed_logins', ['mode' => 'block']);

    $this->artisan('watchtower:simulate')
        ->assertSuccessful()
        ->expectsOutputToContain('Detector failed_logins [block]')
        ->expectsOutputToContain('No real block was logged either');

    onlyDetector('failed_logins', ['mode' => 'disabled']);

    $this->artisan('watchtower:simulate')
        ->assertSuccessful()
        ->expectsOutputToContain('Its mode is `disabled`, so it never runs');
});

it('truncates a long detector table and keeps every address in --json', function () {
    onlyDetector('scanner_paths');

    for ($i = 1; $i <= 26; $i++) {
        wouldHaveBlocked("10.0.1.{$i}", 'scanner_paths', 30);
    }

    $this->artisan('watchtower:simulate')
        ->assertSuccessful()
        ->expectsOutputToContain('… and 1 more. Use --json for the full list.');

    expect(Artisan::call('watchtower:simulate', ['--json' => true]))->toBe(0);
    $json = json_decode(Artisan::output(), true, flags: JSON_THROW_ON_ERROR);

    expect($json['detectors']['scanner_paths']['offenders'])->toHaveCount(26);
});

it('emits the detector report in --json', function () {
    onlyDetector('response_bursts');
    wouldHaveBlocked('10.0.0.9', 'response_bursts', 30, ['user_ids' => [7]]);
    logEntry('10.0.0.5', ['level' => 'warning', 'message' => AutoBlockService::WOULD_HAVE_BLOCKED_MESSAGE, 'context' => '{"detec']);

    expect(Artisan::call('watchtower:simulate', ['--json' => true]))->toBe(0);
    $json = json_decode(Artisan::output(), true, flags: JSON_THROW_ON_ERROR);

    expect($json['unreadable_detector_rows'])->toBe(1)
        ->and($json['detectors']['response_bursts'])->toMatchArray(['enabled' => true, 'mode' => 'warn'])
        ->and($json['detectors']['response_bursts']['offenders'])->toBe([[
            'ip'       => '10.0.0.9',
            'reports'  => 1,
            'first_at' => '2026-09-21T11:30:00+00:00',
            'last_at'  => '2026-09-21T11:30:00+00:00',
            'user_ids' => ['7'],
            'outcomes' => ['blocked' => 1],
        ]]);
});

it('strips control and bidi characters from an outcome before printing it', function () {
    onlyDetector('response_bursts');
    wouldHaveBlocked('10.0.0.9', 'response_bursts', 30, ['in_block_mode' => "bl\u{202E}ocked\u{9B}31m"]);

    $this->artisan('watchtower:simulate')
        ->assertSuccessful()
        ->expectsOutputToContain('blocked31m');
});

it('does not trust a forged line: unknown detectors and non-addresses are set aside, markup is printed as text', function () {
    // The log table is shared; anything can log this message.
    onlyDetector('response_bursts');
    wouldHaveBlocked('10.0.0.9', 'made_up', 30);
    wouldHaveBlocked('not-an-ip', 'response_bursts', 30);
    wouldHaveBlocked('10.0.0.9', 'response_bursts', 30, ['in_block_mode' => '<error>clean</error>', 'user_ids' => [[1]]]);

    $this->artisan('watchtower:simulate')
        ->assertSuccessful()
        ->expectsOutputToContain('<error>clean</error>')
        ->expectsOutputToContain('2 would-have-blocked or auto-blocked line(s) could not be used')
        ->doesntExpectOutputToContain('made_up');
});

it('says a detector switched to warn from the management page is warning, not blocking (#142)', function () {
    config()->set('cache.default', 'array');
    config()->set('watchtower.cache.store', 'array');
    onlyDetector('failed_logins', ['mode' => 'block']);
    app(AutoBlockService::class)->switchToWarn('failed_logins', 'admin@example.com');

    $this->artisan('watchtower:simulate')
        ->expectsOutputToContain('Detector failed_logins [warn] — switched to warn on the management page')
        ->doesntExpectOutputToContain('In block mode its real blocks')
        ->assertSuccessful();
});
