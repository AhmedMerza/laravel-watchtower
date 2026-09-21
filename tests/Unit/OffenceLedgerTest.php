<?php

declare(strict_types=1);

use Watchtower\Models\IpOffence;
use Watchtower\Services\OffenceLedger;

/**
 * These call OffenceLedger directly rather than driving it through
 * AutoBlockService, and that is the point.
 *
 * AutoBlockService::escalatedMinutes() catches \Throwable and falls back to
 * the flat duration, which is right for a ledger that can't be read — but it
 * also means a *bug* in here returns the same number the correct path would
 * have returned for a first offence. A mutation of the first-offence guard
 * survived the whole feature suite that way: it threw on every first offence,
 * was swallowed, and answered 60 regardless. Nothing between the ledger and
 * the assertion here can do that.
 */
beforeEach(function () {
    config()->set('watchtower.auto_block.escalation.enabled', true);
    config()->set('watchtower.auto_block.escalation.repeat_durations', [360, 1440]);
    config()->set('watchtower.auto_block.escalation.decay_days', 30);

    $this->ledger = new OffenceLedger;
});

it('answers the flat duration for a first offence without reaching the ladder', function () {
    expect($this->ledger->durationFor('1.2.3.4', '', 60))->toBe(60)
        ->and(IpOffence::where('ip', '1.2.3.4')->value('offence_count'))->toBe(1);
});

it('climbs a rung per offence and then stays at the top', function () {
    expect($this->ledger->durationFor('1.2.3.4', '', 60))->toBe(60)
        ->and($this->ledger->durationFor('1.2.3.4', '', 60))->toBe(360)
        ->and($this->ledger->durationFor('1.2.3.4', '', 60))->toBe(1440)
        ->and($this->ledger->durationFor('1.2.3.4', '', 60))->toBe(1440);
});

it('answers the flat duration while escalation is off, and writes nothing', function () {
    config()->set('watchtower.auto_block.escalation.enabled', false);

    expect($this->ledger->durationFor('1.2.3.4', '', 60))->toBe(60)
        ->and($this->ledger->durationFor('1.2.3.4', '', 60))->toBe(60)
        ->and(IpOffence::count())->toBe(0);
});

it('never answers less than the flat duration, whatever the ladder says', function () {
    // The config comment and the changelog both promise escalation can
    // lengthen a block and never shorten one. Only this clamp enforces it
    // once an operator edits either setting.
    config()->set('watchtower.auto_block.escalation.repeat_durations', [30]);

    expect($this->ledger->durationFor('1.2.3.4', '', 60))->toBe(60)
        ->and($this->ledger->durationFor('1.2.3.4', '', 60))->toBe(60);
});

it('ignores a repeat_durations that is not a list at all', function () {
    config()->set('watchtower.auto_block.escalation.repeat_durations', 'in a bit');

    expect($this->ledger->durationFor('1.2.3.4', '', 60))->toBe(60)
        ->and($this->ledger->durationFor('1.2.3.4', '', 60))->toBe(60);
});

it('drops the rungs that are not a positive number of minutes and keeps the rest', function () {
    config()->set('watchtower.auto_block.escalation.repeat_durations', ['abc', 3.5, true, 720]);

    expect($this->ledger->durationFor('1.2.3.4', '', 60))->toBe(60)
        ->and($this->ledger->durationFor('1.2.3.4', '', 60))->toBe(720);
});

it('falls back to the default decay window when decay_days is nonsense', function () {
    config()->set('watchtower.auto_block.escalation.decay_days', '');

    expect($this->ledger->durationFor('1.2.3.4', '', 60))->toBe(60);

    // Five days is inside the 30-day default and outside a window of zero —
    // which is what a bare (int) cast of '' would have produced, and would
    // have reset the ladder on every single block.
    IpOffence::where('ip', '1.2.3.4')->update(['last_offence_at' => now()->subDays(5)]);

    expect($this->ledger->durationFor('1.2.3.4', '', 60))->toBe(360);
});

it('keeps a separate count per scope', function () {
    expect($this->ledger->durationFor('1.2.3.4', '', 60))->toBe(60)
        ->and($this->ledger->durationFor('1.2.3.4', '', 60))->toBe(360)
        // Same address, different scope: its own ladder, starting at the
        // bottom.
        ->and($this->ledger->durationFor('1.2.3.4', 'auth', 60))->toBe(60)
        ->and(IpOffence::count())->toBe(2);
});

it('prunes only the ledgers past the decay window, exclusive of the boundary', function () {
    // Frozen, or "exactly 30 days ago" drifts a few microseconds past the
    // threshold between building the row and running the prune, and the
    // boundary case silently becomes the decayed case.
    $this->freezeTime();

    foreach ([31, 30, 5] as $daysAgo) {
        IpOffence::create([
            'ip'               => "10.0.0.{$daysAgo}",
            'scope'            => '',
            'offence_count'    => 2,
            'first_offence_at' => now()->subDays($daysAgo),
            'last_offence_at'  => now()->subDays($daysAgo),
        ]);
    }

    expect($this->ledger->prune())->toBe(1)
        ->and(IpOffence::orderBy('ip')->pluck('ip')->all())->toBe(['10.0.0.30', '10.0.0.5']);
});
