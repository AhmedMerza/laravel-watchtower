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

    $offender = ($this->run)(['count' => 10, 'window_minutes' => 5], sharedIp: 3)['offenders'][0];

    // Held back at the crossing and at every tick after it, until the burst
    // falls out of the window: warnings, and never a block.
    expect($offender['blocks'])->toBe(0)
        ->and($offender['warnings'])->toBe(5);
});

it('does not flag the guard when it is switched off', function () {
    burst('10.0.0.1', 10, 30);

    foreach ([1, 2, 3] as $i => $userId) {
        logEntry('10.0.0.1', [
            'user_id'     => $userId,
            'occurred_at' => now()->copy()->subMinutes(30)->addSeconds($i),
        ]);
    }

    $offender = ($this->run)(['count' => 10, 'window_minutes' => 5], sharedIp: 0)['offenders'][0];

    expect($offender['blocks'])->toBe(1)
        ->and($offender['warnings'])->toBe(0);
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
        ->and($offender['warnings'])->toBe(0);
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

    // Count the paging queries rather than measuring memory. An earlier
    // version of this test asserted a `memory_get_usage()` delta and was
    // FLAKY: that delta includes the PDO result buffer, the query log and
    // whatever the previous test left for the collector, none of which this
    // code controls — it passed locally and on eight CI cells, then failed
    // on the ninth under a different random order seed (6.0MB against a 4MB
    // ceiling). Query count is deterministic and tests the thing that
    // actually matters here: that the walk pages instead of fetching 2500
    // rows at once, and that it terminates rather than looping on a keyset
    // it cannot advance.
    //
    // The memory bound is structural, not measured: the buffer is a fixed
    // `array_fill(0, $threshold, 0)` that never grows.
    $pages = 0;

    DB::listen(function ($query) use (&$pages): void {
        // The matching rows' pages only, not the shared-IP guard's walk
        // over the signed-in ones.
        if (str_contains($query->sql, 'order by') && str_contains($query->sql, 'limit')
            && ! str_contains($query->sql, 'user_id')) {
            $pages++;
        }
    });

    $result = ($this->run)(['count' => 2000, 'window_minutes' => 5]);

    // 2500 rows at a 1000-row page size: two full pages and a short one that
    // ends the walk. Fewer means rows were skipped; more means it is not
    // stopping on a short page.
    expect($result['offenders'])->toHaveCount(1)
        ->and($result['offenders'][0]['blocks'])->toBe(1)
        ->and($pages)->toBe(3);
});

/*
|--------------------------------------------------------------------------
| Engine parity — the cases where the simulation used to disagree with the
| live AutoBlockService about what would actually have happened.
|--------------------------------------------------------------------------
*/

it('reports a scoped rule as a scoped block, not as a warning, when the shared-IP guard trips', function () {
    // AutoBlockService::blockOrReport() converts a shared-IP hold-back into a
    // real scoped block for any non-global rule — that is what scopes are
    // for. Reporting it as "would have been a warning" is exactly backwards.
    config()->set('watchtower.scopes', ['auth']);

    burst('10.0.0.1', 10, 30);

    foreach ([1, 2, 3] as $i => $userId) {
        logEntry('10.0.0.1', [
            'user_id'     => $userId,
            'occurred_at' => now()->copy()->subMinutes(30)->addSeconds($i),
        ]);
    }

    $offender = ($this->run)([
        'count'          => 10,
        'window_minutes' => 5,
        'scope'          => 'auth',
    ], sharedIp: 3)['offenders'][0];

    expect($offender['blocks'])->toBe(1)
        ->and($offender['warnings'])->toBe(0)
        ->and($offender['downgraded_to_scope'])->toBe('auth');
});

it('still holds a global rule back when the shared-IP guard trips', function () {
    burst('10.0.0.1', 10, 30);

    foreach ([1, 2, 3] as $i => $userId) {
        logEntry('10.0.0.1', [
            'user_id'     => $userId,
            'occurred_at' => now()->copy()->subMinutes(30)->addSeconds($i),
        ]);
    }

    $offender = ($this->run)(['count' => 10, 'window_minutes' => 5], sharedIp: 3)['offenders'][0];

    expect($offender['blocks'])->toBe(0)
        ->and($offender['warnings'])->toBe(5)
        ->and($offender['downgraded_to_scope'])->toBeNull();
});

it('blocks a later crossing that no longer looks shared, after a first one that did (#92)', function () {
    // Two hours ago the address carried three signed-in users and was held
    // back; half an hour ago it crossed again with nobody signed in. The
    // engine re-measures the guard on every tick, so the second crossing is
    // a block — judging the guard once, at the first, called it a warning.
    burst('10.0.0.1', 10, 120);

    foreach ([1, 2, 3] as $i => $userId) {
        logEntry('10.0.0.1', [
            'user_id'     => $userId,
            'occurred_at' => now()->copy()->subMinutes(120)->addSeconds($i),
        ]);
    }

    burst('10.0.0.1', 10, 30);

    $offender = ($this->run)(['count' => 10, 'window_minutes' => 5], sharedIp: 3)['offenders'][0];

    expect($offender['blocks'])->toBe(1)
        ->and($offender['warnings'])->toBe(5)
        ->and($offender['last_block_at'])->toBe(now()->copy()->subMinutes(30)->addSeconds(9)->toIso8601String());
});

it('does not let a held-back crossing hide the crossings after it (#92)', function () {
    // The users sign in at the start of an attack that keeps going. A
    // held-back crossing opens no hold, so once they age out of the window
    // the engine blocks — well inside block_duration_minutes of the first
    // crossing, which the old replay treated as already served.
    foreach ([1, 2, 3] as $i => $userId) {
        logEntry('10.0.0.1', [
            'level'       => 'info',
            'user_id'     => $userId,
            'occurred_at' => now()->copy()->subMinutes(30)->addSeconds($i),
        ]);
    }

    for ($i = 0; $i < 45; $i++) {
        logEntry('10.0.0.1', [
            'level'       => 'error',
            'occurred_at' => now()->copy()->subMinutes(30)->addSeconds($i * 20),
        ]);
    }

    $offender = ($this->run)(['level' => 'error', 'count' => 10, 'window_minutes' => 5], sharedIp: 3)['offenders'][0];

    expect($offender['blocks'])->toBe(1)
        ->and($offender['warnings'])->toBe(3);
});

it('blocks on a later tick once the users age out, with no new row to prompt it (#92)', function () {
    // The users were seen three minutes before the burst, so the crossing is
    // held back, and two ticks later they have left the window while the
    // burst has not. Nothing is logged then; the engine blocks anyway.
    foreach ([1, 2, 3] as $i => $userId) {
        logEntry('10.0.0.1', [
            'level'       => 'info',
            'user_id'     => $userId,
            'occurred_at' => now()->copy()->subMinutes(33)->addSeconds($i),
        ]);
    }

    burst('10.0.0.1', 10, 30, ['level' => 'error']);

    $offender = ($this->run)(['level' => 'error', 'count' => 10, 'window_minutes' => 5], sharedIp: 3)['offenders'][0];

    expect($offender['warnings'])->toBe(2)
        ->and($offender['blocks'])->toBe(1)
        ->and($offender['last_block_at'])->toBe(now()->copy()->subMinutes(30)->addSeconds(9 + 120)->toIso8601String());
});

it('keeps counting a user whose earlier row ages out while a later one is still in the window (#92)', function () {
    // User 1's second row arrives after the address is first held back. At
    // the next tick it enters the window as the first one leaves, so user 1
    // is still signed in there. Forgetting them with their oldest row would
    // drop the count to two and block a minute early.
    foreach ([[1, 34], [2, 31], [3, 31], [1, 29]] as [$userId, $minutesAgo]) {
        logEntry('10.0.0.1', [
            'level'       => 'info',
            'user_id'     => $userId,
            'occurred_at' => now()->copy()->subMinutes($minutesAgo),
        ]);
    }

    burst('10.0.0.1', 10, 30, ['level' => 'error']);

    $offender = ($this->run)(['level' => 'error', 'count' => 10, 'window_minutes' => 5], sharedIp: 3)['offenders'][0];

    // Held back until users 2 and 3 age out four ticks later.
    expect($offender['warnings'])->toBe(4)
        ->and($offender['blocks'])->toBe(1)
        ->and($offender['last_block_at'])->toBe(now()->copy()->subMinutes(30)->addSeconds(9 + 240)->toIso8601String());
});

it('simulates nothing for a rule whose scope no route declares', function () {
    // AutoBlockService::run() skips such a rule outright, so a report of
    // what it "would have caught" describes a rule that never runs.
    config()->set('watchtower.scopes', ['auth']);

    burst('10.0.0.1', 20, 30);

    $result = ($this->run)([
        'count'          => 5,
        'window_minutes' => 5,
        'scope'          => 'nonsense',
    ]);

    expect($result['scope_declared'])->toBeFalse()
        ->and($result['offenders'])->toBe([]);
});

it('catches a burst that straddles the start of the period', function () {
    // The window is wall-clock and knows nothing about --days. Two matching
    // rows just before the cutoff and one just after IS a 3-in-5-minutes
    // crossing, and the engine would have blocked it. Reading only from the
    // cutoff would drop the first two and miss the block — under-reporting,
    // the one direction this is not allowed to err in.
    $from = now()->copy()->subDays(7);

    logEntry('10.0.0.1', ['occurred_at' => $from->copy()->subMinutes(2)]);
    logEntry('10.0.0.1', ['occurred_at' => $from->copy()->subMinutes(1)]);
    logEntry('10.0.0.1', ['occurred_at' => $from->copy()->addMinutes(1)]);

    $result = ($this->run)(['count' => 3, 'window_minutes' => 5], days: 7);

    expect($result['offenders'])->toHaveCount(1)
        ->and($result['offenders'][0]['blocks'])->toBe(1);
});

it('does not report a crossing that happened entirely before the period', function () {
    // Read, so the boundary case above works — but not reported, because it
    // belongs to the week the operator did not ask about.
    $from = now()->copy()->subDays(7);

    foreach ([5, 4, 3] as $minutes) {
        logEntry('10.0.0.1', ['occurred_at' => $from->copy()->subMinutes($minutes)]);
    }

    expect(($this->run)(['count' => 3, 'window_minutes' => 5], days: 7)['offenders'])->toBe([]);
});

it('leaves out an address the never_block list protects', function () {
    config()->set('watchtower.never_block', ['10.0.0.1']);

    burst('10.0.0.1', 20, 30);
    burst('10.0.0.2', 20, 30);

    $result = ($this->run)(['count' => 5, 'window_minutes' => 5]);

    expect(array_column($result['offenders'], 'ip'))->toBe(['10.0.0.2'])
        ->and($result['never_blocked'])->toBe(['10.0.0.1']);
});

it('leaves out an address the never_auto_block list protects', function () {
    // Automation cannot block it, and a rule is automation.
    config()->set('watchtower.never_auto_block', ['10.0.0.1']);

    burst('10.0.0.1', 20, 30);

    $result = ($this->run)(['count' => 5, 'window_minutes' => 5]);

    expect($result['offenders'])->toBe([])
        ->and($result['never_blocked'])->toBe(['10.0.0.1']);
});

it('treats a level of "0" as no filter, exactly as the engine does', function () {
    // AutoBlockService gates on `if ($level)`, under which "0" is falsy.
    burst('10.0.0.1', 10, 30, ['level' => 'error']);

    $result = ($this->run)(['level' => '0', 'count' => 5, 'window_minutes' => 5]);

    expect($result['level'])->toBeNull()
        ->and($result['offenders'])->toHaveCount(1);
});

it('keeps counting through a block when the window is longer than the block', function () {
    // The buffer is deliberately not cleared when a block fires: the engine
    // re-reads a wall-clock window every tick, it does not start counting
    // afresh. With window(30) > duration(5) that difference is observable —
    // clearing would need 4 fresh rows after every block and would
    // under-report.
    foreach ([60, 52, 44, 36, 28, 20, 12, 4] as $minutesAgo) {
        logEntry('10.0.0.1', ['occurred_at' => now()->copy()->subMinutes($minutesAgo)]);
    }

    $result = ($this->run)(['count' => 4, 'window_minutes' => 30], duration: 5);

    // Blocks at 36, 31, 26, 20, 15, 10 and 4 minutes ago. Each new row
    // re-crosses a window that still holds its three predecessors, and the
    // lapses at 31, 26, 15 and 10 re-block with nothing new logged, because
    // four rows are still inside the window. The lapses at 21 and 5 find
    // only three.
    expect($result['offenders'][0]['blocks'])->toBe(7)
        ->and($result['offenders'][0]['first_block_at'])->toBe(now()->copy()->subMinutes(36)->toIso8601String())
        ->and($result['offenders'][0]['last_block_at'])->toBe(now()->copy()->subMinutes(4)->toIso8601String());
});

it('re-checks once a minute rather than hanging when the block duration is not positive', function (int $duration) {
    // A lapse at or before the tick that set it would re-evaluate that same
    // moment forever. The engine can't re-check sooner than its next
    // once-a-minute run, so neither does the simulator: blocks at +9s, +69s,
    // +129s, +189s and +249s, and at +309s the first row has left the window.
    burst('10.0.0.1', 10, 30);

    $result = ($this->run)(['count' => 10, 'window_minutes' => 5], duration: $duration);

    expect($result['offenders'][0]['blocks'])->toBe(5);
})->with([0, -5]);

/**
 * Pins the OUTPUT contract, not the tie-break that implements it.
 *
 * Deleting `strcmp` from the usort leaves this green: SQLite hands back
 * GROUP BY results in key order and PHP's sort is stable, so the addresses
 * arrive sorted before usort sees them. The explicit tie-break is therefore
 * belt-and-braces over an ordering no standard promises — MySQL and Postgres
 * are free to return groups in any order at all, and this test would be the
 * thing that noticed on those drivers. Kept deliberately, and labelled so
 * nobody reads it as proving the tie-break itself.
 */
it('orders two equally busy addresses by address, so --json diffs cleanly', function () {
    burst('10.0.0.9', 10, 30);
    burst('10.0.0.2', 10, 30);

    expect(array_column(($this->run)(['count' => 10, 'window_minutes' => 5])['offenders'], 'ip'))
        ->toBe(['10.0.0.2', '10.0.0.9']);
});

it('orders addresses with no blocks by warnings before address', function () {
    // Both held back at every crossing. 10.0.0.9's burst stays over the
    // threshold for five ticks, 10.0.0.2's for one, so the busier address
    // leads even though it sorts second by name.
    foreach (['10.0.0.9' => 1, '10.0.0.2' => 30] as $ip => $spacing) {
        foreach ([1, 2, 3] as $i => $userId) {
            logEntry($ip, [
                'level'       => 'info',
                'user_id'     => $userId,
                'occurred_at' => now()->copy()->subMinutes(30)->addSeconds($i),
            ]);
        }

        for ($i = 0; $i < 10; $i++) {
            logEntry($ip, ['occurred_at' => now()->copy()->subMinutes(30)->addSeconds($i * $spacing)]);
        }
    }

    $offenders = ($this->run)(['level' => 'error', 'count' => 10, 'window_minutes' => 5], sharedIp: 3)['offenders'];

    expect(array_column($offenders, 'ip'))->toBe(['10.0.0.9', '10.0.0.2'])
        ->and(array_column($offenders, 'warnings'))->toBe([5, 1])
        ->and(array_column($offenders, 'blocks'))->toBe([0, 0]);
});
