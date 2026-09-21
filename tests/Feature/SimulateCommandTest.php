<?php

declare(strict_types=1);

use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use Illuminate\Support\Str;

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
        ->toMatchArray(['ip' => '10.0.0.1', 'blocks' => 1, 'distinct_users' => 1]);
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

it('succeeds quietly when no rules are configured', function () {
    config()->set('watchtower.auto_block.rules', []);

    // Not a failure: an app running only the real-time detectors has no
    // rules by design, and a scripted caller shouldn't treat that as broken.
    $this->artisan('watchtower:simulate')
        ->assertSuccessful()
        ->expectsOutputToContain('No auto-block rules are configured');
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

it('warns when the shared-IP guard would have downgraded a block', function () {
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
        ->expectsOutputToContain('held back by the shared-IP guard');
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
