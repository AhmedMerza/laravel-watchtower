<?php

declare(strict_types=1);

use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use Watchtower\Services\RuleSimulator;

beforeEach(function () {
    // Frozen so that "3 minutes ago" means the same thing to the seed data
    // and to the window the simulator slides over it. A test that seeds
    // relative to a moving now() and asserts on window boundaries is a test
    // that fails once a minute.
    Carbon::setTestNow('2026-09-21 12:00:00');

    $this->simulator = new RuleSimulator;

    $this->run = function (array $rule, int $days = 7, int $duration = 60, int $sharedIp = 3) {
        return $this->simulator->simulate(
            $rule,
            0,
            now()->copy()->subDays($days),
            now(),
            $duration,
            $sharedIp,
            'warn',
        );
    };
});

afterEach(function () {
    Carbon::setTestNow();
});

/** A burst of $count entries from $ip, one per second, ending $minutesAgo ago. */
function burst(string $ip, int $count, int $minutesAgo, array $attributes = []): void
{
    $start = now()->copy()->subMinutes($minutesAgo);

    for ($i = 0; $i < $count; $i++) {
        logEntry($ip, array_merge([
            'occurred_at' => $start->copy()->addSeconds($i),
        ], $attributes));
    }
}

it('reports exactly one would-be block for a burst that crosses the threshold once', function () {
    burst('10.0.0.1', 10, 30);

    $result = ($this->run)([
        'level'          => 'error',
        'count'          => 10,
        'window_minutes' => 5,
    ]);

    expect($result['offenders'])->toHaveCount(1)
        ->and($result['offenders'][0]['ip'])->toBe('10.0.0.1')
        ->and($result['offenders'][0]['blocks'])->toBe(1);
});

it('reports nothing when the burst is one entry short of the threshold', function () {
    burst('10.0.0.1', 9, 30);

    expect(($this->run)([
        'level'          => 'error',
        'count'          => 10,
        'window_minutes' => 5,
    ])['offenders'])->toBe([]);
});

it('does not fire when the entries are spread wider than the window', function () {
    // 10 entries, but one every 2 minutes — never 10 inside any 5 minutes.
    for ($i = 0; $i < 10; $i++) {
        logEntry('10.0.0.1', ['occurred_at' => now()->copy()->subMinutes(120 - ($i * 2))]);
    }

    expect(($this->run)([
        'level'          => 'error',
        'count'          => 5,
        'window_minutes' => 5,
    ])['offenders'])->toBe([]);
});

it('counts one block per block duration, not one per matching entry', function () {
    // Three hours of steady noise, well over threshold throughout. The
    // engine blocks, and then ignores the address until the block lapses,
    // so a 60-minute duration over ~3 hours is 3 blocks — not 180.
    for ($i = 0; $i < 180; $i++) {
        logEntry('10.0.0.1', ['occurred_at' => now()->copy()->subMinutes(180 - $i)]);
    }

    $result = ($this->run)([
        'count'          => 3,
        'window_minutes' => 5,
    ], duration: 60);

    expect($result['offenders'][0]['blocks'])->toBe(3);
});

it('lets a shorter block duration fire more often over the same history', function () {
    for ($i = 0; $i < 180; $i++) {
        logEntry('10.0.0.1', ['occurred_at' => now()->copy()->subMinutes(180 - $i)]);
    }

    $blocks = fn (int $duration) => ($this->run)([
        'count'          => 3,
        'window_minutes' => 5,
    ], duration: $duration)['offenders'][0]['blocks'];

    expect($blocks(60))->toBe(3)
        ->and($blocks(30))->toBe(6);
});

it('honours the level filter', function () {
    burst('10.0.0.1', 10, 30, ['level' => 'warning']);

    expect(($this->run)([
        'level'          => 'error',
        'count'          => 5,
        'window_minutes' => 5,
    ])['offenders'])->toBe([]);

    expect(($this->run)([
        'level'          => 'warning',
        'count'          => 5,
        'window_minutes' => 5,
    ])['offenders'])->toHaveCount(1);
});

it('honours the message_contains filter', function () {
    burst('10.0.0.1', 10, 30, ['message' => 'Failed login for admin']);
    burst('10.0.0.2', 10, 30, ['message' => 'Disk almost full']);

    $result = ($this->run)([
        'message_contains' => 'Failed login',
        'count'            => 5,
        'window_minutes'   => 5,
    ]);

    expect($result['offenders'])->toHaveCount(1)
        ->and($result['offenders'][0]['ip'])->toBe('10.0.0.1');
});

it('ignores history outside the requested period', function () {
    burst('10.0.0.1', 20, 60 * 24 * 10);   // ten days ago

    expect(($this->run)(['count' => 5, 'window_minutes' => 5], days: 7)['offenders'])->toBe([]);
    expect(($this->run)(['count' => 5, 'window_minutes' => 5], days: 14)['offenders'])->toHaveCount(1);
});

it('reports distinct signed-in users per address', function () {
    burst('10.0.0.1', 10, 30);

    // Same address, three different people signed in, plus a repeat.
    foreach ([7, 8, 9, 7] as $i => $userId) {
        logEntry('10.0.0.1', [
            'user_id'     => $userId,
            'occurred_at' => now()->copy()->subMinutes(30)->addSeconds($i),
        ]);
    }

    expect(($this->run)(['count' => 10, 'window_minutes' => 5])['offenders'][0]['distinct_users'])
        ->toBe(3);
});

it('flags an address the shared-IP guard would have held back', function () {
    burst('10.0.0.1', 10, 30);

    foreach ([1, 2, 3] as $i => $userId) {
        logEntry('10.0.0.1', [
            'user_id'     => $userId,
            'occurred_at' => now()->copy()->subMinutes(30)->addSeconds($i),
        ]);
    }

    $result = ($this->run)(['count' => 10, 'window_minutes' => 5], sharedIp: 3);

    expect($result['offenders'][0]['held_back_by_shared_ip_guard'])->toBeTrue();
});

it('does not flag the guard when it is switched off', function () {
    burst('10.0.0.1', 10, 30);

    foreach ([1, 2, 3] as $i => $userId) {
        logEntry('10.0.0.1', [
            'user_id'     => $userId,
            'occurred_at' => now()->copy()->subMinutes(30)->addSeconds($i),
        ]);
    }

    expect(($this->run)(['count' => 10, 'window_minutes' => 5], sharedIp: 0)['offenders'][0]['held_back_by_shared_ip_guard'])
        ->toBeFalse();
});

it('counts signed-in traffic that never matched the rule, as the false-positive signal', function () {
    burst('10.0.0.1', 10, 30, ['level' => 'error']);

    // Four signed-in requests that the rule has no quarrel with.
    for ($i = 0; $i < 4; $i++) {
        logEntry('10.0.0.1', [
            'level'       => 'info',
            'user_id'     => 42,
            'occurred_at' => now()->copy()->subMinutes(20)->addSeconds($i),
        ]);
    }

    expect(($this->run)([
        'level'          => 'error',
        'count'          => 10,
        'window_minutes' => 5,
    ])['offenders'][0]['authenticated_rows_not_matching'])->toBe(4);
});

it('does not count matching signed-in rows as innocent traffic', function () {
    // Every row matches the rule AND carries a user, so nothing is innocent.
    burst('10.0.0.1', 10, 30, ['level' => 'error', 'user_id' => 42]);

    expect(($this->run)([
        'level'          => 'error',
        'count'          => 10,
        'window_minutes' => 5,
    ])['offenders'][0]['authenticated_rows_not_matching'])->toBe(0);
});

it('never counts an anonymous address as having users', function () {
    burst('10.0.0.1', 10, 30);

    $offender = ($this->run)(['count' => 10, 'window_minutes' => 5])['offenders'][0];

    expect($offender['distinct_users'])->toBe(0)
        ->and($offender['authenticated_rows_not_matching'])->toBe(0)
        ->and($offender['held_back_by_shared_ip_guard'])->toBeFalse();
});

it('skips rows with no ip address at all', function () {
    for ($i = 0; $i < 20; $i++) {
        logEntry('10.0.0.1', ['occurred_at' => now()->copy()->subMinutes(30)->addSeconds($i)]);
    }

    DB::table('log_entries')->insert([
        'id'          => Str::ulid(),
        'level'       => 'error',
        'message'     => 'Console error, no request behind it',
        'ip_address'  => null,
        'occurred_at' => now()->copy()->subMinutes(30),
        'created_at'  => now(),
        'updated_at'  => now(),
    ]);

    $result = ($this->run)(['count' => 5, 'window_minutes' => 5]);

    expect($result['offenders'])->toHaveCount(1)
        ->and($result['offenders'][0]['ip'])->toBe('10.0.0.1');
});

it('ranks the busiest address first', function () {
    // .1 earns two blocks, .2 earns one.
    for ($i = 0; $i < 90; $i++) {
        logEntry('10.0.0.1', ['occurred_at' => now()->copy()->subMinutes(120 - $i)]);
    }
    burst('10.0.0.2', 10, 30);

    $result = ($this->run)(['count' => 5, 'window_minutes' => 5], duration: 60);

    expect(array_column($result['offenders'], 'ip'))->toBe(['10.0.0.1', '10.0.0.2']);
});

it('reports the rule it replayed, so the operator knows which one to edit', function () {
    $result = $this->simulator->simulate(
        ['level' => 'error', 'message_contains' => 'boom', 'count' => 4, 'window_minutes' => 9, 'scope' => 'auth'],
        3,
        now()->copy()->subDays(7),
        now(),
        60,
        3,
        'block',
    );

    expect($result)->toMatchArray([
        'rule_index'       => 3,
        'mode'             => 'block',
        'level'            => 'error',
        'message_contains' => 'boom',
        'threshold'        => 4,
        'window_minutes'   => 9,
        'scope'            => 'auth',
    ]);
});

it('treats a zero threshold as one entry rather than dividing by nothing', function () {
    logEntry('10.0.0.1', ['occurred_at' => now()->copy()->subMinutes(30)]);

    $result = ($this->run)(['count' => 0, 'window_minutes' => 5]);

    expect($result['threshold'])->toBe(1)
        ->and($result['offenders'])->toHaveCount(1);
});

it('streams an address whose history spans many keyset pages', function () {
    // Every row shares ONE timestamp, and there are more of them than the
    // 1000-row page size. That is the exact shape a keyset on occurred_at
    // alone gets wrong: after the first page, `occurred_at > $lastAt` skips
    // every remaining row at that same second, and the walk silently ends
    // 1500 rows early. A burst inside a single second is also the traffic
    // this whole command exists to look at, so it is not a contrived case.
    //
    // Spreading these across several seconds would NOT catch it — the page
    // boundary would land on a timestamp change and the bug would hide.
    $start = now()->copy()->subMinutes(30);

    $rows = [];

    for ($i = 0; $i < 2500; $i++) {
        $rows[] = [
            'id'          => (string) Str::ulid(),
            'level'       => 'error',
            'message'     => 'Boom',
            'ip_address'  => '10.0.0.1',
            'user_id'     => null,
            'occurred_at' => $start,
            'created_at'  => now(),
            'updated_at'  => now(),
        ];
    }

    foreach (array_chunk($rows, 500) as $chunk) {
        DB::table('log_entries')->insert($chunk);
    }

    $before = memory_get_usage();
    $result = ($this->run)(['count' => 2000, 'window_minutes' => 5]);
    $used = memory_get_usage() - $before;

    // The point of the ring buffer: it holds `count` timestamps, not the
    // 2500 rows it walked past. If the stream ever collects rows instead of
    // yielding them, this is what notices.
    expect($result['offenders'])->toHaveCount(1)
        ->and($result['offenders'][0]['blocks'])->toBe(1)
        ->and($used)->toBeLessThan(4 * 1024 * 1024);
});
