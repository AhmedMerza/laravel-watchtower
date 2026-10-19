<?php

declare(strict_types=1);

use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use Watchtower\Services\SignalReplay;
use Watchtower\Support\BlockScope;
use Watchtower\Support\SignalLog;

beforeEach(function () {
    Carbon::setTestNow('2026-09-21 12:00:00');

    // Defaults: 3 in 5 min, guard at 2 users, warn, app-wide, 60-min hold.
    $this->replay = fn (array $o = []): array => (new SignalReplay)->replay(
        'response_bursts',
        $o['count'] ?? 3,
        $o['window'] ?? 5,
        $o['shared'] ?? 2,
        $o['mode'] ?? 'warn',
        $o['scope'] ?? BlockScope::GLOBAL,
        $o['duration'] ?? 60,
        now()->subDays(1),
        now(),
    );
});

afterEach(function () {
    Carbon::setTestNow();
});

/** One counted signal, $minutesAgo before the frozen now. */
function signal(string $ip, float $minutesAgo, ?string $userId = null, string $detector = 'response_bursts'): void
{
    DB::table(SignalLog::TABLE)->insert([
        'detector'    => $detector,
        'ip'          => $ip,
        'user_id'     => $userId,
        'occurred_at' => now()->subSeconds((int) round($minutesAgo * 60)),
    ]);
}

/** @return array<string, int> crossings per address */
function crossings(array $offenders): array
{
    return array_column($offenders, 'reports', 'ip');
}

it('counts in a window fixed from its first hit, not one that slides', function () {
    // 0, 4 and 6 minutes in: a sliding 5-minute window holds 4 and 6 together
    // with a third hit at 8; a fixed one restarts at 6 and needs 6, 8, 9.
    signal('10.0.0.1', 600);
    signal('10.0.0.1', 596);
    signal('10.0.0.1', 594);
    signal('10.0.0.1', 592);

    expect(($this->replay)())->toBe([]);

    signal('10.0.0.1', 591);

    expect(crossings(($this->replay)()))->toBe(['10.0.0.1' => 1]);
});

it('starts the count again at every crossing, so the next one needs a full count', function () {
    foreach ([600, 599.9, 599.8] as $m) {
        signal('10.0.0.1', $m);
    }

    // Past the 1-minute hold and inside one window: a counter left at 3
    // would cross on this single hit.
    signal('10.0.0.1', 598.5);

    expect(crossings(($this->replay)(['duration' => 1])))->toBe(['10.0.0.1' => 1]);

    signal('10.0.0.1', 598.4);
    signal('10.0.0.1', 598.3);

    expect(crossings(($this->replay)(['duration' => 1])))->toBe(['10.0.0.1' => 2]);
});

it('holds a warn-mode decision for the block duration while the address keeps counting', function () {
    // One hit every 10 seconds, 0 to 80.
    foreach (range(0, 8) as $i) {
        signal('10.0.0.1', 600 - $i / 6);
    }

    // Crossing at 20s, held to 80s. Hits 4-8 kept counting through the hold
    // (to 5), so the 9th, at 80s, decides again: a replay that skipped held
    // rows would have it at 1.
    expect(crossings(($this->replay)()))->toBe(['10.0.0.1' => 1])
        ->and(crossings(($this->replay)(['duration' => 1])))->toBe(['10.0.0.1' => 2]);
});

it('counts nothing from an address block mode has taken out of play', function () {
    foreach (range(0, 5) as $i) {
        signal('10.0.0.1', 600 - $i * 0.1);
    }

    $offenders = ($this->replay)(['mode' => 'block']);

    expect(crossings($offenders))->toBe(['10.0.0.1' => 1])
        ->and($offenders[0]['outcomes'])->toBe(['blocked' => 1]);

    // Once the block lapses the address starts from nothing.
    foreach (range(0, 2) as $i) {
        signal('10.0.0.1', 530 - $i * 0.1);
    }

    expect(crossings(($this->replay)(['mode' => 'block'])))->toBe(['10.0.0.1' => 2]);
});

it('re-measures the shared-IP guard at every crossing rather than holding it', function () {
    foreach (range(0, 5) as $i) {
        signal('10.0.0.1', 600 - $i * 0.1, (string) ($i % 2));
    }

    $offenders = ($this->replay)(['mode' => 'block']);

    expect($offenders[0]['reports'])->toBe(2)
        ->and($offenders[0]['outcomes'])->toBe(['shared IP' => 2])
        ->and($offenders[0]['user_ids'])->toEqualCanonicalizing(['0', '1']);

    // Guard off: the first crossing blocks, and nothing more is counted.
    expect(($this->replay)(['mode' => 'block', 'shared' => 0])[0]['outcomes'])->toBe(['blocked' => 1]);
});

it('forgets the users of a window that has closed', function () {
    signal('10.0.0.1', 600, '7');
    signal('10.0.0.1', 594);
    signal('10.0.0.1', 593.9, '8');
    signal('10.0.0.1', 593.8);

    // User 7 was in the window before; only 8 is in the one that crossed.
    expect(($this->replay)(['mode' => 'block'])[0]['outcomes'])->toBe(['blocked' => 1]);
});

it('holds a never_auto_block refusal only for the listed address, not its whole /64', function () {
    config()->set('watchtower.never_auto_block', ['2001:db8::1']);

    foreach (range(0, 2) as $i) {
        signal('2001:db8::1', 600 - $i * 0.1);
    }

    foreach (range(0, 2) as $i) {
        signal('2001:db8::2', 599 - $i * 0.1);
    }

    $offenders = ($this->replay)(['mode' => 'block']);

    expect(array_column($offenders, 'outcomes', 'ip'))->toBe([
        '2001:db8::1' => ['never_auto_block' => 1],
        '2001:db8::2' => ['blocked' => 1],
    ]);
});

it('counts addresses in one IPv6 /64 together, as a block would cover them', function () {
    signal('2001:db8::1', 600);
    signal('2001:db8::2', 599.9);
    signal('2001:db8::3', 599.8);
    signal('2001:db9::1', 599.7);

    expect(crossings(($this->replay)()))->toBe(['2001:db8::3' => 1]);
});

it('replays only the detector it is asked about, inside the period', function () {
    foreach (range(0, 2) as $i) {
        signal('10.0.0.1', 600 - $i * 0.1, null, 'scanner_paths');
        signal('10.0.0.2', 2000 + $i * 0.1);
    }

    expect(($this->replay)())->toBe([]);
});
