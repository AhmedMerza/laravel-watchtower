<?php

declare(strict_types=1);

namespace Watchtower\Services;

use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;
use Watchtower\Models\IpOffence;
use Watchtower\Support\FailureWindow;

/**
 * Remembers how many times an address has earned an auto-block, and turns
 * that count into how long the next one should last.
 *
 * A fixed hour is only a pause for someone who comes back, so the second
 * block is longer than the first and the fourth is longer again. The count
 * decays: an address that stays quiet for `decay_days` starts from the
 * bottom of the ladder, so an address reassigned to somebody else isn't
 * serving a sentence the last tenant earned.
 *
 * Kept out of BlacklistService on purpose — manual blocks and blocks
 * arriving over sync carry an explicit `expires_at` from their caller, and
 * escalation must not reach them. Only AutoBlockService asks.
 */
class OffenceLedger
{
    private const DEFAULT_DECAY_DAYS = 30;

    /**
     * Record one auto-block against this target, and answer how many minutes
     * it should last.
     *
     * `$target` is the address a block will actually cover — the caller
     * normalizes first, so an IPv6 client hopping inside its own /64 keeps
     * one ledger rather than a fresh one per address.
     *
     * @param  int  $defaultMinutes  the flat `block_duration_minutes`, which
     *                               is both the first rung of every ladder
     *                               and the answer when escalation is off.
     */
    public function durationFor(string $target, string $scope, int $defaultMinutes): int
    {
        if (! config('watchtower.auto_block.escalation.enabled', false)) {
            return $defaultMinutes;
        }

        $count = $this->record($target, $scope);
        $ladder = $this->ladder();

        // The first offence is the flat duration, so the ladder's rungs are
        // the second block onward — see the config comment. An empty or
        // unusable ladder leaves every block at the flat duration, which is
        // exactly the behaviour of escalation being switched off.
        if ($count <= 1 || $ladder === []) {
            return $defaultMinutes;
        }

        // Never below the flat duration. The ladder exists to lengthen a
        // block, and a rung under block_duration_minutes would make a repeat
        // offence cheaper than the first one — which the config comment and
        // the changelog both promise cannot happen, and which nothing
        // otherwise enforces once an operator edits either setting. Clamped
        // rather than dropped, so that raising block_duration_minutes past a
        // rung shortens nothing and simply flattens the bottom of the ladder.
        return max($defaultMinutes, $ladder[min($count - 2, count($ladder) - 1)]);
    }

    /**
     * Drop the ledgers that have gone quiet for longer than the decay
     * window, and answer how many were removed.
     *
     * These rows are already spent — record() starts a decayed ledger again
     * from 1 whether the row is there or not — so this is housekeeping, not
     * behaviour. It lives here rather than in the cleanup command so that
     * `decay_days` is read and parsed in exactly one place: a prune that
     * disagreed with the counter about the window would either delete
     * ladders that were still climbing or keep rows nothing will ever read.
     */
    public function prune(): int
    {
        return IpOffence::where('last_offence_at', '<', now()->subDays($this->decayDays()))->delete();
    }

    /**
     * Add this offence to the address's ledger and answer the running count,
     * starting again from 1 if the last one has decayed.
     *
     * Locked, because reading the count into PHP and writing count+1 back is
     * a read-modify-write: two blocks decided for one address at the same
     * instant would both read the same number and both write the same
     * increment, losing one **silently**. That is the traffic this feature
     * exists to punish, so the ladder would climb slowest exactly during a
     * burst.
     *
     * ponytail: the lock can only hold a row that already exists, so two
     * blocks racing to record an address's FIRST offence can still collide on
     * the (ip, scope) unique index. That one throws rather than passing
     * quietly: the caller treats it as "no escalation this time", falls back
     * to the flat duration, and the next offence picks the ladder back up.
     * Upgrade path if it ever shows up in practice: an upsert with the
     * increment expressed in SQL, which needs a per-driver CASE for decay.
     */
    private function record(string $target, string $scope): int
    {
        return DB::transaction(function () use ($target, $scope): int {
            $offence = IpOffence::where('ip', $target)
                ->where('scope', $scope)
                ->lockForUpdate()
                ->first()
                ?? new IpOffence(['ip' => $target, 'scope' => $scope]);

            $decayed = $offence->last_offence_at === null
                || $offence->last_offence_at->lt(now()->subDays($this->decayDays()));

            $offence->offence_count = $decayed ? 1 : $offence->offence_count + 1;
            $offence->first_offence_at = $decayed ? now() : ($offence->first_offence_at ?? now());
            $offence->last_offence_at = now();
            $offence->save();

            return $offence->offence_count;
        });
    }

    /**
     * The configured durations for a repeat offence, in minutes, lowest rung
     * first. The last rung repeats for every offence past the end.
     *
     * A rung of 0 or less is dropped rather than used: it would put
     * `expires_at` at or before now, which is a block that has already
     * expired — an escalating ladder that silently stops blocking anyone is
     * the worst thing this feature could do, so a typo falls back to the
     * flat duration instead.
     *
     * @return list<int>
     */
    private function ladder(): array
    {
        $configured = config('watchtower.auto_block.escalation.repeat_durations', []);

        if (! is_array($configured)) {
            $this->warnOnce('repeat_durations is not a list of minutes, so every auto-block uses the flat duration.', [
                'configured' => $configured,
            ]);

            return [];
        }

        $rungs = [];

        foreach ($configured as $value) {
            $minutes = match (true) {
                is_int($value) => $value,
                is_string($value) && ctype_digit(trim($value)) => (int) trim($value),
                default => 0,
            };

            if ($minutes > 0) {
                $rungs[] = $minutes;
            }
        }

        if (count($rungs) !== count($configured)) {
            $this->warnOnce('repeat_durations has entries that are not a positive number of minutes, and those rungs were dropped.', [
                'configured' => $configured,
                'using'      => $rungs,
            ]);
        }

        return $rungs;
    }

    /**
     * Days without an offence before a ledger starts again from the bottom.
     *
     * Parsed rather than cast for the reason shared_ip_user_threshold gives:
     * a blank or misspelled env value casts to 0, and a decay window of 0
     * days would reset every ladder on every block — escalation would look
     * enabled and never escalate.
     */
    private function decayDays(): int
    {
        $configured = config('watchtower.auto_block.escalation.decay_days', self::DEFAULT_DECAY_DAYS);

        if (is_int($configured) && $configured > 0) {
            return $configured;
        }

        if (is_string($configured) && ctype_digit(trim($configured)) && (int) trim($configured) > 0) {
            return (int) trim($configured);
        }

        $this->warnOnce('decay_days is not a whole number of days above zero, so the default was used.', [
            'configured' => $configured,
            'using'      => self::DEFAULT_DECAY_DAYS,
        ]);

        return self::DEFAULT_DECAY_DAYS;
    }

    /**
     * Throttled, because the scheduled tick reads this config once per
     * offender and the detectors once per block — a misconfigured ladder
     * would otherwise write a line for each.
     *
     * @param  array<string, mixed>  $context
     */
    private function warnOnce(string $message, array $context): void
    {
        if (FailureWindow::isOpen('escalation')) {
            return;
        }

        FailureWindow::open('escalation');

        Log::channel(config('watchtower.log_channel', 'stack'))
            ->warning('Watchtower: '.$message, $context);
    }
}
