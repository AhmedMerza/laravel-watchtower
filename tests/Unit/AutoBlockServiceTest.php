<?php

declare(strict_types=1);

use Illuminate\Database\QueryException;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Queue;
use Illuminate\Support\Str;
use Watchtower\Enums\BlockSource;
use Watchtower\Exceptions\NeverAutoBlockException;
use Watchtower\Models\BlacklistedIp;
use Watchtower\Services\AutoBlockService;
use Watchtower\Services\BlacklistCache;
use Watchtower\Services\BlacklistService;
use Watchtower\Services\OffenceLedger;
use Watchtower\Support\HitWindow;

beforeEach(function () {
    // Use the array cache store — real cache, no Redis-facade mocking.
    config()->set('cache.default', 'array');
    config()->set('watchtower.cache.store', 'array');
    Cache::flush();

    Event::fake();
    Queue::fake();

    config()->set('watchtower.auto_block.enabled', true);
    config()->set('watchtower.auto_block.block_duration_minutes', 60);

    // Armed by default here. The shipped default is 'warn' (covered by its
    // own test below); these cases are about thresholds, windows and
    // whitelists, so they need the mode that actually writes a block.
    config()->set('watchtower.auto_block.mode', 'block');

    $this->cache = new BlacklistCache;
    $this->blacklist = new BlacklistService($this->cache);
    $this->service = new AutoBlockService($this->blacklist, new HitWindow, new OffenceLedger);
});

it('does nothing when auto-block is disabled', function () {
    config()->set('watchtower.auto_block.enabled', false);

    // Create a log entry that would normally trigger a block
    DB::table('log_entries')->insert([
        'id'          => Str::ulid(),
        'level'       => 'error',
        'message'     => 'Something went wrong',
        'ip_address'  => '1.2.3.4',
        'occurred_at' => now(),
        'created_at'  => now(),
        'updated_at'  => now(),
    ]);

    config()->set('watchtower.auto_block.rules', [[
        'level'            => 'error',
        'message_contains' => null,
        'count'            => 1,
        'window_minutes'   => 5,
    ]]);

    $this->service->run();

    $this->assertDatabaseMissing('blacklisted_ips', ['ip' => '1.2.3.4']);
});

it('does nothing when no rules are configured', function () {
    config()->set('watchtower.auto_block.rules', []);

    $this->service->run();

    $this->assertDatabaseCount('blacklisted_ips', 0);
});

it('blocks an IP that exceeds the rule threshold', function () {
    config()->set('watchtower.auto_block.rules', [[
        'level'            => 'error',
        'message_contains' => null,
        'count'            => 3,
        'window_minutes'   => 5,
    ]]);

    foreach (range(1, 3) as $i) {
        DB::table('log_entries')->insert([
            'id'          => Str::ulid(),
            'level'       => 'error',
            'message'     => 'Error occurred',
            'ip_address'  => '5.5.5.5',
            'occurred_at' => now(),
            'created_at'  => now(),
            'updated_at'  => now(),
        ]);
    }

    $this->service->run();

    $this->assertDatabaseHas('blacklisted_ips', [
        'ip'     => '5.5.5.5',
        'source' => 'auto',
    ]);
});

it('does not block an IP below the threshold', function () {
    config()->set('watchtower.auto_block.rules', [[
        'level'            => 'error',
        'message_contains' => null,
        'count'            => 10,
        'window_minutes'   => 5,
    ]]);

    foreach (range(1, 5) as $i) {
        DB::table('log_entries')->insert([
            'id'          => Str::ulid(),
            'level'       => 'error',
            'message'     => 'Error occurred',
            'ip_address'  => '6.6.6.6',
            'occurred_at' => now(),
            'created_at'  => now(),
            'updated_at'  => now(),
        ]);
    }

    $this->service->run();

    $this->assertDatabaseMissing('blacklisted_ips', ['ip' => '6.6.6.6']);
});

it('matches message_contains filter correctly', function () {
    config()->set('watchtower.auto_block.rules', [[
        'level'            => null,
        'message_contains' => '404',
        'count'            => 2,
        'window_minutes'   => 5,
    ]]);

    // This IP sends 404 messages — should be blocked
    foreach (range(1, 2) as $i) {
        DB::table('log_entries')->insert([
            'id'          => Str::ulid(),
            'level'       => 'warning',
            'message'     => 'Route not found 404',
            'ip_address'  => '7.7.7.7',
            'occurred_at' => now(),
            'created_at'  => now(),
            'updated_at'  => now(),
        ]);
    }

    // This IP sends different messages — should not be blocked
    foreach (range(1, 2) as $i) {
        DB::table('log_entries')->insert([
            'id'          => Str::ulid(),
            'level'       => 'warning',
            'message'     => 'Something else happened',
            'ip_address'  => '8.8.8.8',
            'occurred_at' => now(),
            'created_at'  => now(),
            'updated_at'  => now(),
        ]);
    }

    $this->service->run();

    $this->assertDatabaseHas('blacklisted_ips', ['ip' => '7.7.7.7']);
    $this->assertDatabaseMissing('blacklisted_ips', ['ip' => '8.8.8.8']);
});

it('skips IPs in the never-block whitelist', function () {
    config()->set('watchtower.never_block', ['9.9.9.9']);
    config()->set('watchtower.auto_block.rules', [[
        'level'            => 'error',
        'message_contains' => null,
        'count'            => 1,
        'window_minutes'   => 5,
    ]]);

    DB::table('log_entries')->insert([
        'id'          => Str::ulid(),
        'level'       => 'error',
        'message'     => 'Error',
        'ip_address'  => '9.9.9.9',
        'occurred_at' => now(),
        'created_at'  => now(),
        'updated_at'  => now(),
    ]);

    $this->service->run();

    $this->assertDatabaseMissing('blacklisted_ips', ['ip' => '9.9.9.9']);
});

it('lets a failed block write surface instead of skipping it as whitelisted', function () {
    config()->set('watchtower.auto_block.rules', [[
        'level'            => 'error',
        'message_contains' => null,
        'count'            => 1,
        'window_minutes'   => 5,
    ]]);

    DB::table('log_entries')->insert([
        'id'          => Str::ulid(),
        'level'       => 'error',
        'message'     => 'Error',
        'ip_address'  => '9.9.9.9',
        'occurred_at' => now(),
        'created_at'  => now(),
        'updated_at'  => now(),
    ]);

    failBlacklistInserts();

    expect(fn () => $this->service->run())->toThrow(QueryException::class);
});

it('skips IPs that are already blocked', function () {
    config()->set('watchtower.auto_block.rules', [[
        'level'            => 'error',
        'message_contains' => null,
        'count'            => 1,
        'window_minutes'   => 5,
    ]]);

    BlacklistedIp::create([
        'ip'         => '3.3.3.3',
        'source'     => BlockSource::Manual,
        'source_env' => 'testing',
    ]);

    // Pin the cache state directly — `isBlocked('3.3.3.3')` should return
    // true before AutoBlockService runs, so the rule's `if ($this->blacklist->isBlocked($ip)) continue;`
    // skip path fires. Without this, the test passes for the wrong reason
    // (BlacklistService::block dedupes via updateOrCreate).
    Cache::store('array')->put('watchtower:blacklist:ip:3.3.3.3', '', 3600);

    DB::table('log_entries')->insert([
        'id'          => Str::ulid(),
        'level'       => 'error',
        'message'     => 'Error',
        'ip_address'  => '3.3.3.3',
        'occurred_at' => now(),
        'created_at'  => now(),
        'updated_at'  => now(),
    ]);

    $this->service->run();

    // Should still be exactly 1 record — no duplicate
    $this->assertDatabaseCount('blacklisted_ips', 1);
});

it('ignores log entries outside the time window', function () {
    config()->set('watchtower.auto_block.rules', [[
        'level'            => 'error',
        'message_contains' => null,
        'count'            => 1,
        'window_minutes'   => 5,
    ]]);

    DB::table('log_entries')->insert([
        'id'          => Str::ulid(),
        'level'       => 'error',
        'message'     => 'Old error',
        'ip_address'  => '4.4.4.4',
        'occurred_at' => now()->subMinutes(10),
        'created_at'  => now(),
        'updated_at'  => now(),
    ]);

    $this->service->run();

    $this->assertDatabaseMissing('blacklisted_ips', ['ip' => '4.4.4.4']);
});

/*
 * Mode tests — per-rule `mode` overrides global `watchtower.auto_block.mode`.
 * Modes: 'block' (default), 'warn' (log but don't block), 'disabled' (skip).
 */

it('warn mode logs a would-have-blocked entry and does NOT block', function () {
    config()->set('watchtower.auto_block.mode', 'warn');
    config()->set('watchtower.auto_block.rules', [[
        'level'            => 'error',
        'message_contains' => null,
        'count'            => 2,
        'window_minutes'   => 5,
    ]]);

    foreach (range(1, 2) as $i) {
        DB::table('log_entries')->insert([
            'id'          => Str::ulid(),
            'level'       => 'error',
            'message'     => 'Boom',
            'ip_address'  => '11.11.11.11',
            'occurred_at' => now(),
            'created_at'  => now(),
            'updated_at'  => now(),
        ]);
    }

    $logChannel = Mockery::mock();
    $logChannel->shouldReceive('warning')
        ->once()
        ->withArgs(function (string $message, array $context): bool {
            return $message === 'Watchtower: would-have-blocked (auto-block did not block)'
                && $context['would_have_blocked'] === true
                && $context['ip'] === '11.11.11.11'
                && $context['threshold'] === 2
                && $context['window_minutes'] === 5
                && $context['not_blocked_because'] === 'warn mode'
                && str_contains($context['hint'], 'WATCHTOWER_AUTO_BLOCK_MODE=block')
                && is_int($context['rule_index']);
        });
    Log::shouldReceive('channel')->andReturn($logChannel);

    $this->service->run();

    $this->assertDatabaseMissing('blacklisted_ips', ['ip' => '11.11.11.11']);
});

it('runs in warn mode when no mode is configured anywhere', function () {
    // No mode key set anywhere — a rule is a dry run until someone arms it.
    config()->offsetUnset('watchtower.auto_block.mode');
    config()->set('watchtower.auto_block.rules', [[
        'level'            => 'error',
        'message_contains' => null,
        'count'            => 1,
        'window_minutes'   => 5,
    ]]);

    DB::table('log_entries')->insert([
        'id'          => Str::ulid(),
        'level'       => 'error',
        'message'     => 'Boom',
        'ip_address'  => '12.12.12.12',
        'occurred_at' => now(),
        'created_at'  => now(),
        'updated_at'  => now(),
    ]);

    $logChannel = Mockery::mock();
    $logChannel->shouldReceive('warning')
        ->once()
        ->withArgs(fn (string $message, array $context): bool => $context['not_blocked_because'] === 'warn mode');
    Log::shouldReceive('channel')->andReturn($logChannel);

    $this->service->run();

    $this->assertDatabaseMissing('blacklisted_ips', ['ip' => '12.12.12.12']);
});

it('per-rule mode overrides global mode (rule=block wins over global=warn)', function () {
    config()->set('watchtower.auto_block.mode', 'warn');
    config()->set('watchtower.auto_block.rules', [[
        'level'            => 'error',
        'message_contains' => null,
        'count'            => 1,
        'window_minutes'   => 5,
        'mode'             => 'block', // per-rule override
    ]]);

    DB::table('log_entries')->insert([
        'id'          => Str::ulid(),
        'level'       => 'error',
        'message'     => 'Boom',
        'ip_address'  => '13.13.13.13',
        'occurred_at' => now(),
        'created_at'  => now(),
        'updated_at'  => now(),
    ]);

    $this->service->run();

    $this->assertDatabaseHas('blacklisted_ips', ['ip' => '13.13.13.13', 'source' => 'auto']);
});

it('per-rule mode overrides global mode (rule=warn wins over global=block)', function () {
    config()->set('watchtower.auto_block.mode', 'block');
    config()->set('watchtower.auto_block.rules', [[
        'level'            => 'error',
        'message_contains' => null,
        'count'            => 1,
        'window_minutes'   => 5,
        'mode'             => 'warn', // per-rule override
    ]]);

    DB::table('log_entries')->insert([
        'id'          => Str::ulid(),
        'level'       => 'error',
        'message'     => 'Boom',
        'ip_address'  => '14.14.14.14',
        'occurred_at' => now(),
        'created_at'  => now(),
        'updated_at'  => now(),
    ]);

    // Mock the log channel so we don't need real logging infra
    $logChannel = Mockery::mock();
    $logChannel->shouldReceive('warning')->once();
    Log::shouldReceive('channel')->andReturn($logChannel);

    $this->service->run();

    $this->assertDatabaseMissing('blacklisted_ips', ['ip' => '14.14.14.14']);
});

it('disabled mode skips the rule entirely (no block, no warn log)', function () {
    config()->set('watchtower.auto_block.rules', [[
        'level'            => 'error',
        'message_contains' => null,
        'count'            => 1,
        'window_minutes'   => 5,
        'mode'             => 'disabled',
    ]]);

    DB::table('log_entries')->insert([
        'id'          => Str::ulid(),
        'level'       => 'error',
        'message'     => 'Boom',
        'ip_address'  => '15.15.15.15',
        'occurred_at' => now(),
        'created_at'  => now(),
        'updated_at'  => now(),
    ]);

    // Pin the contract: disabled mode must not emit ANY warn-level log entry.
    // DB-absence alone wouldn't catch a regression where a refactored
    // disabled-mode path still ran applyRule() and emitted warns. Allow other
    // log methods so unrelated code paths (debug, etc.) don't false-positive
    // this assertion if anything else happens to resolve a channel.
    $logChannel = Mockery::mock();
    $logChannel->shouldNotReceive('warning');
    $logChannel->shouldReceive('debug')->zeroOrMoreTimes();
    $logChannel->shouldReceive('info')->zeroOrMoreTimes();
    $logChannel->shouldReceive('error')->zeroOrMoreTimes();
    Log::shouldReceive('channel')->andReturn($logChannel);

    $this->service->run();

    $this->assertDatabaseMissing('blacklisted_ips', ['ip' => '15.15.15.15']);
});

it('invalid global mode value falls back to warn', function () {
    config()->set('watchtower.auto_block.mode', 'this-is-not-a-mode');
    config()->set('watchtower.auto_block.rules', [[
        'level'            => 'error',
        'message_contains' => null,
        'count'            => 1,
        'window_minutes'   => 5,
    ]]);

    DB::table('log_entries')->insert([
        'id'          => Str::ulid(),
        'level'       => 'error',
        'message'     => 'Boom',
        'ip_address'  => '16.16.16.16',
        'occurred_at' => now(),
        'created_at'  => now(),
        'updated_at'  => now(),
    ]);

    $logChannel = Mockery::mock();
    $logChannel->shouldReceive('warning')->once();
    Log::shouldReceive('channel')->andReturn($logChannel);

    $this->service->run();

    $this->assertDatabaseMissing('blacklisted_ips', ['ip' => '16.16.16.16']);
});

/*
 * Shared-IP guard (#22) — many real users sit behind one public address
 * (carrier-grade NAT, office gateways, VPN exits), so a rule tuned for one
 * bad actor must not take the whole gateway down with it.
 */

function expectWarning(string $notBlockedBecause): void
{
    $logChannel = Mockery::mock();
    $logChannel->shouldReceive('warning')
        ->once()
        ->withArgs(fn (string $message, array $context): bool => $context['not_blocked_because'] === $notBlockedBecause);
    $logChannel->shouldReceive('debug')->zeroOrMoreTimes();
    Log::shouldReceive('channel')->andReturn($logChannel);
}

it('warns instead of blocking when enough signed-in users share the address', function () {
    config()->set('watchtower.auto_block.shared_ip_user_threshold', 3);
    config()->set('watchtower.auto_block.rules', [[
        'level'            => 'error',
        'message_contains' => null,
        'count'            => 3,
        'window_minutes'   => 5,
    ]]);

    foreach ([1, 2, 3] as $userId) {
        logEntry('20.20.20.20', ['user_id' => $userId]);
    }

    expectWarning('shared IP');

    $this->service->run();

    $this->assertDatabaseMissing('blacklisted_ips', ['ip' => '20.20.20.20']);
});

it('still blocks when the same volume comes from a single signed-in user', function () {
    config()->set('watchtower.auto_block.shared_ip_user_threshold', 3);
    config()->set('watchtower.auto_block.rules', [[
        'level'            => 'error',
        'message_contains' => null,
        'count'            => 3,
        'window_minutes'   => 5,
    ]]);

    foreach (range(1, 3) as $i) {
        logEntry('21.21.21.21', ['user_id' => 7]);
    }

    $this->service->run();

    $this->assertDatabaseHas('blacklisted_ips', ['ip' => '21.21.21.21', 'source' => 'auto']);
});

it('still blocks anonymous traffic, which belongs to nobody the guard can count', function () {
    config()->set('watchtower.auto_block.shared_ip_user_threshold', 3);
    config()->set('watchtower.auto_block.rules', [[
        'level'            => 'error',
        'message_contains' => null,
        'count'            => 3,
        'window_minutes'   => 5,
    ]]);

    foreach (range(1, 3) as $i) {
        logEntry('22.22.22.22');
    }

    $this->service->run();

    $this->assertDatabaseHas('blacklisted_ips', ['ip' => '22.22.22.22', 'source' => 'auto']);
});

it('counts users across all the traffic from the address, not just the rows the rule matched', function () {
    // The case the guard exists for: one buggy client throws every error
    // while other people browse the same gateway fine. Counting only the
    // matching rows would see one user and block all of them.
    config()->set('watchtower.auto_block.shared_ip_user_threshold', 3);
    config()->set('watchtower.auto_block.rules', [[
        'level'            => 'error',
        'message_contains' => null,
        'count'            => 3,
        'window_minutes'   => 5,
    ]]);

    foreach (range(1, 3) as $i) {
        logEntry('23.23.23.23', ['user_id' => 1]);
    }

    foreach ([2, 3] as $userId) {
        logEntry('23.23.23.23', ['level' => 'info', 'message' => 'Browsing', 'user_id' => $userId]);
    }

    expectWarning('shared IP');

    $this->service->run();

    $this->assertDatabaseMissing('blacklisted_ips', ['ip' => '23.23.23.23']);
});

it('switches the shared-IP guard off at a threshold of 0', function () {
    config()->set('watchtower.auto_block.shared_ip_user_threshold', 0);
    config()->set('watchtower.auto_block.rules', [[
        'level'            => 'error',
        'message_contains' => null,
        'count'            => 3,
        'window_minutes'   => 5,
    ]]);

    foreach ([1, 2, 3] as $userId) {
        logEntry('24.24.24.24', ['user_id' => $userId]);
    }

    $this->service->run();

    $this->assertDatabaseHas('blacklisted_ips', ['ip' => '24.24.24.24', 'source' => 'auto']);
});

/*
 * never_auto_block (#22) — automation leaves these alone, an admin still can't
 * be stopped by them. That is the whole difference from never_block.
 */

it('downgrades an automated block to a warning for an IP in never_auto_block', function () {
    config()->set('watchtower.never_auto_block', ['25.25.25.25']);
    config()->set('watchtower.auto_block.rules', [[
        'level'            => 'error',
        'message_contains' => null,
        'count'            => 1,
        'window_minutes'   => 5,
    ]]);

    logEntry('25.25.25.25');

    expectWarning('never_auto_block');

    $this->service->run();

    $this->assertDatabaseMissing('blacklisted_ips', ['ip' => '25.25.25.25']);
});

it('matches a never_auto_block CIDR range', function () {
    config()->set('watchtower.never_auto_block', ['203.0.113.0/24']);
    config()->set('watchtower.auto_block.rules', [[
        'level'            => 'error',
        'message_contains' => null,
        'count'            => 1,
        'window_minutes'   => 5,
    ]]);

    logEntry('203.0.113.7');

    expectWarning('never_auto_block');

    $this->service->run();

    $this->assertDatabaseMissing('blacklisted_ips', ['ip' => '203.0.113.7']);
});

it('lets an admin block an IP in never_auto_block by hand', function () {
    config()->set('watchtower.never_auto_block', ['26.26.26.26']);

    $this->blacklist->block('26.26.26.26', ['reason' => 'Blocked by hand']);

    $this->assertDatabaseHas('blacklisted_ips', ['ip' => '26.26.26.26', 'source' => 'manual']);
});

/*
 * Review fixes (#55) — each of these is a way a misconfiguration or a
 * caller's sloppiness could have quietly removed a guard.
 */

it('falls back to warn for an invalid per-rule mode rather than inheriting an armed global', function () {
    // The dangerous shape: armed globally, and a rule that meant to opt out
    // of that but misspelled it. Inheriting the global would block.
    config()->set('watchtower.auto_block.mode', 'block');
    config()->set('watchtower.auto_block.rules', [[
        'level'            => 'error',
        'message_contains' => null,
        'count'            => 1,
        'window_minutes'   => 5,
        'mode'             => 'warm', // typo for 'warn'
    ]]);

    logEntry('30.30.30.30');

    expectWarning('warn mode');

    $this->service->run();

    $this->assertDatabaseMissing('blacklisted_ips', ['ip' => '30.30.30.30']);
});

it('keeps the shared-IP guard on when the threshold is not a number', function () {
    // 0 means "off", so a blank or misspelled env value must NOT read as 0.
    config()->set('watchtower.auto_block.shared_ip_user_threshold', '');
    config()->set('watchtower.auto_block.rules', [[
        'level'            => 'error',
        'message_contains' => null,
        'count'            => 3,
        'window_minutes'   => 5,
    ]]);

    foreach ([1, 2, 3] as $userId) {
        logEntry('31.31.31.31', ['user_id' => $userId]);
    }

    $logChannel = Mockery::mock();
    $logChannel->shouldReceive('warning')
        ->with(Mockery::pattern('/shared_ip_user_threshold is not a whole number/'), Mockery::any())
        ->once();
    $logChannel->shouldReceive('warning')
        ->withArgs(fn (string $message, array $context): bool => ($context['not_blocked_because'] ?? null) === 'shared IP')
        ->once();
    Log::shouldReceive('channel')->andReturn($logChannel);

    $this->service->run();

    // Guard still active on the default of 3, so this is a warning not a block.
    $this->assertDatabaseMissing('blacklisted_ips', ['ip' => '31.31.31.31']);
});

it('still honours an explicit threshold of 0 as off, not as a misconfiguration', function () {
    config()->set('watchtower.auto_block.shared_ip_user_threshold', '0');
    config()->set('watchtower.auto_block.rules', [[
        'level'            => 'error',
        'message_contains' => null,
        'count'            => 3,
        'window_minutes'   => 5,
    ]]);

    foreach ([1, 2, 3] as $userId) {
        logEntry('32.32.32.32', ['user_id' => $userId]);
    }

    $this->service->run();

    $this->assertDatabaseHas('blacklisted_ips', ['ip' => '32.32.32.32', 'source' => 'auto']);
});

it('applies never_auto_block to a caller that passes the source as a string', function () {
    // The model's enum cast accepts 'auto', so a strict enum comparison
    // alone would have let this straight past the guard.
    config()->set('watchtower.never_auto_block', ['33.33.33.33']);

    expect(fn () => $this->blacklist->block('33.33.33.33', ['source' => 'auto']))
        ->toThrow(NeverAutoBlockException::class);

    $this->assertDatabaseMissing('blacklisted_ips', ['ip' => '33.33.33.33']);
});
