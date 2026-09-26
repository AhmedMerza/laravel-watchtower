<?php

declare(strict_types=1);

namespace Watchtower\Services;

use Carbon\CarbonInterface;
use Illuminate\Database\Query\Builder;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use Watchtower\Support\BlockScope;
use Watchtower\Support\NeverBlockList;

/**
 * Replays the configured auto-block rules over log history, and answers the
 * question `warn` mode takes a week to answer: what would this rule have
 * done last Tuesday?
 *
 * This is deliberately a separate class from AutoBlockService rather than a
 * mode of it. AutoBlockService blocks — it writes rows, fires events, queues
 * a sync push and rebuilds a cache — and a backtest that shared that code
 * would be one forgotten branch away from blocking a week of addresses
 * because somebody ran a report. Nothing here writes anything, and there is
 * no path from here into BlacklistService for one to be missed.
 *
 * ## How the replay differs from the engine, on purpose
 *
 * `AutoBlockService::run()` is a scheduled task: it evaluates every rule
 * once a minute against `[now - window, now]`. Replaying that faithfully
 * would mean one grouped query per minute per rule — 10,080 queries for a
 * week — so this walks the rows instead and slides the window over them.
 *
 * The cost is granularity. The engine notices a threshold crossing at the
 * next tick; this notices it at the row that crossed it, up to a minute
 * earlier. It therefore never reports FEWER blocks than the engine would
 * have issued, which is the safe direction for a report whose whole purpose
 * is "show me what I'd be turning on".
 *
 * ## Why two passes
 *
 * The issue this was built for assumed an `(ip_address, occurred_at)` index.
 * LogScope doesn't have one — `ip_address` and `occurred_at` are indexed
 * separately, and the composites are all `(something, occurred_at)`. So the
 * shape that would have been natural (walk the period one window at a time,
 * carrying per-address state) would hold state for every address seen in the
 * period, which on a busy week is the thing the memory criterion rules out.
 *
 * Instead:
 *
 * 1. NARROW. One grouped aggregate over the period per rule. An address
 *    cannot cross a threshold of N inside a window unless it has at least N
 *    matching rows somewhere in the period, so `having count(*) >= N` is a
 *    sound over-approximation and it prunes hard. A rule that names a level
 *    rides `(level, occurred_at)`; one that doesn't rides `occurred_at`.
 *    Either way the counting happens in the database and no rows reach PHP.
 *
 * 2. REPLAY. Per surviving address, stream only that address's rows in time
 *    order and slide the window over them. One address at a time, so peak
 *    memory is one address's ring buffer rather than the table.
 */
final class RuleSimulator
{
    /** Rows per keyset page while streaming one address's history. */
    private const CHUNK = 1000;

    /** The engine's scheduler tick: how soon a held-back address is looked at again. */
    private const TICK_SECONDS = 60;

    /**
     * Replay one rule across `[$from, $to]`.
     *
     * `$durationMinutes` is what the engine would have blocked for, and it
     * matters to the count: an address that keeps hammering is blocked
     * ONCE per duration, not once per burst, so a simulation that ignored
     * the block lifetime would report a number of blocks no operator would
     * ever have seen.
     *
     * @param  array<string, mixed>  $rule
     * @return array{
     *     rule_index: int,
     *     mode: string,
     *     level: string|null,
     *     message_contains: string|null,
     *     threshold: int,
     *     window_minutes: int,
     *     scope: string|null,
     *     scope_declared: bool,
     *     never_blocked: list<string>,
     *     offenders: list<array{
     *         ip: string,
     *         blocks: int,
     *         warnings: int,
     *         first_block_at: string,
     *         last_block_at: string,
     *         distinct_users: int,
     *         users_at_first_block: int,
     *         authenticated_rows_not_matching: int,
     *         downgraded_to_scope: string|null
     *     }>
     * }
     */
    public function simulate(
        array $rule,
        int $ruleIndex,
        CarbonInterface $from,
        CarbonInterface $to,
        int $durationMinutes,
        int $sharedIpThreshold,
        string $mode,
    ): array {
        $table = $this->table();

        $windowMinutes = (int) ($rule['window_minutes'] ?? 5);
        // Clamped for the same reason the ring buffer below is sized on it:
        // a rule with `count => 0` asks the engine for `having count(*) >= 0`,
        // which is every address that has a row at all. One row is the
        // honest reading of that, and it keeps the buffer non-empty.
        $threshold = max(1, (int) ($rule['count'] ?? 10));
        $level = $this->stringOrNull($rule['level'] ?? null);
        $messageContains = $this->stringOrNull($rule['message_contains'] ?? null);
        $scope = $this->stringOrNull($rule['scope'] ?? null);

        // A scope no route declares makes AutoBlockService::run() skip the
        // rule outright — resolveScope() throws and the loop `continue`s. So
        // the honest simulation of such a rule is "this never runs", not a
        // report of everything it would have caught if it did.
        $scopeDeclared = $scope === null || BlockScope::isDeclared($scope);

        $shape = [
            'rule_index'       => $ruleIndex,
            'mode'             => $mode,
            'level'            => $level,
            'message_contains' => $messageContains,
            'threshold'        => $threshold,
            'window_minutes'   => $windowMinutes,
            'scope'            => $scope,
            'scope_declared'   => $scopeDeclared,
            'never_blocked'    => [],
            'offenders'        => [],
        ];

        if (! $scopeDeclared) {
            return $shape;
        }

        // Read from BEFORE the requested period, by one window, and report
        // only crossings inside it. A rule's window is wall-clock and does
        // not know about `--days`: an address with two matching rows just
        // before the cutoff and a third just after HAS crossed a 3-in-5-min
        // threshold, and the engine would have blocked it. Bounding the read
        // at `$from` would drop the first two and miss the block entirely —
        // under-reporting, which is the one direction this is not allowed to
        // err in.
        $readFrom = $from->copy()->subMinutes($windowMinutes);

        $offenders = [];
        $neverBlocked = [];

        foreach ($this->candidates($table, $level, $messageContains, $readFrom, $to, $threshold) as $ip) {
            $replayed = $this->replay(
                $table, $level, $messageContains, $ip, $readFrom, $to,
                $windowMinutes, $threshold, $durationMinutes, $from,
                $scope === null ? $sharedIpThreshold : 0,
            );

            if ($replayed['span'] === null) {
                continue;
            }

            // The engine would have refused this one whatever the rule said:
            // BlacklistService::block() throws for either allow-list and
            // blockOrReport() catches it. Reporting it as a would-be block
            // would point the operator at an address that is already safe —
            // and these are exactly the addresses (their own office, a
            // partner) they most need an accurate answer about.
            if (NeverBlockList::refusesAutoBlock($ip)) {
                $neverBlocked[] = $ip;

                continue;
            }

            [$first, $last] = $replayed['span'];
            $usersAtFirstBlock = $this->distinctUsers(
                $table, $ip, $first->copy()->subMinutes($windowMinutes), $first,
            );

            $offenders[] = [
                'ip'     => $ip,
                'blocks' => $replayed['blocks'],

                // Crossings the shared-IP guard held back on a global rule:
                // one per simulated tick, as the engine logs one per tick.
                'warnings' => $replayed['warnings'],

                // The first and last crossing reported, block or warning.
                'first_block_at'       => $first->toIso8601String(),
                'last_block_at'        => $last->toIso8601String(),
                'distinct_users'       => $this->distinctUsers($table, $ip, $from, $to),
                'users_at_first_block' => $usersAtFirstBlock,

                // The false-positive signal. Authenticated traffic from this
                // address that never matched the rule is, by construction,
                // somebody signed in doing something the rule has no quarrel
                // with — and a block would have taken it away from them.
                'authenticated_rows_not_matching' => $this->authenticatedRows($table, $ip, $from, $to, null, null)
                    - $this->authenticatedRows($table, $ip, $from, $to, $level, $messageContains),

                // Mirrors blockOrReport()'s `$downgraded`: on a scoped rule a
                // shared address is the case scopes exist for, so the engine
                // blocks it in scope rather than holding it back. A label
                // only — every crossing of a scoped rule is already counted
                // as a block either way. Computed against the window the
                // LIVE guard would have read, not the period-wide figure,
                // which is an upper bound and would predict downgrades that
                // never happen.
                'downgraded_to_scope' => $scope !== null && $sharedIpThreshold > 0 && $usersAtFirstBlock >= $sharedIpThreshold
                    ? $scope
                    : null,
            ];
        }

        // Busiest first: the report is read top-down and the address with the
        // most would-be blocks is the one the operator is deciding about.
        // The address tie-break keeps two equally-busy addresses in a stable
        // order, so `--json` diffs cleanly run to run.
        usort($offenders, static fn (array $a, array $b): int => $b['blocks'] <=> $a['blocks']
            ?: $b['warnings'] <=> $a['warnings']
            ?: strcmp($a['ip'], $b['ip']));

        sort($neverBlocked);

        return [...$shape, 'never_blocked' => $neverBlocked, 'offenders' => $offenders];
    }

    /**
     * Addresses that could possibly cross the threshold, cheaply.
     *
     * `having count(*) >= threshold` over the whole period is a superset of
     * the addresses that cross it inside any single window — the replay is
     * what decides which of them actually do. Getting the superset in one
     * aggregate is what stops this from touching the table again per address
     * it was never going to report.
     *
     * @return list<string>
     */
    private function candidates(
        string $table,
        ?string $level,
        ?string $messageContains,
        CarbonInterface $from,
        CarbonInterface $to,
        int $threshold,
    ): array {
        /** @var list<string> */
        return $this->matching($table, $level, $messageContains)
            ->select('ip_address')
            ->whereNotNull('ip_address')
            ->where('occurred_at', '>=', $from)
            ->where('occurred_at', '<=', $to)
            ->groupBy('ip_address')
            ->havingRaw('count(*) >= ?', [$threshold])
            ->pluck('ip_address')
            ->map(static fn ($ip): string => (string) $ip)
            ->all();
    }

    /**
     * Slide the rule's window along one address's history and record every
     * moment the engine would have blocked it, or held a block back.
     *
     * The buffer holds at most `$threshold` timestamps, which is the whole
     * trick behind the memory criterion: the only question ever asked of it
     * is "are there $threshold of these inside the window", so an address
     * that logged a million rows costs the same as one that logged fifty.
     *
     * Rows keep accumulating while the simulated block is in force, and the
     * buffer is deliberately NOT cleared when one fires. The engine re-reads
     * a wall-clock window on every tick; it does not start counting afresh
     * after a block. Clearing here would under-report any rule whose window
     * is longer than the block duration.
     *
     * The shared-IP guard is judged at every crossing, against the window
     * that crossing would have read, because the engine re-measures it on
     * every tick and a held-back crossing opens no hold (#71, #86). So a
     * held-back crossing starts no block clock: the address is looked at
     * again one tick later, and again, until its rows fall out of the window
     * or it stops looking shared — at which point it is blocked, even if no
     * new row arrived to prompt it. Judging the guard once, at the first
     * crossing, reported "warnings, not blocks" for addresses the armed
     * engine blocks (#92). `$sharedIpThreshold` is 0 for a scoped rule: the
     * guard narrows that block rather than holding it back, so every
     * crossing is a block and the user count is never needed.
     *
     * `$reportFrom` is where the REQUESTED period starts. Rows before it are
     * read and counted — they are what makes a crossing at the boundary
     * visible at all — but a crossing before it belongs to the week the
     * operator didn't ask about, so it is not reported.
     *
     * @return array{blocks: int, warnings: int, span: array{CarbonInterface, CarbonInterface}|null}
     *                                                                                               span is the first and last crossing reported, block or warning
     */
    private function replay(
        string $table,
        ?string $level,
        ?string $messageContains,
        string $ip,
        CarbonInterface $from,
        CarbonInterface $to,
        int $windowMinutes,
        int $threshold,
        int $durationMinutes,
        CarbonInterface $reportFrom,
        int $sharedIpThreshold,
    ): array {
        $windowSeconds = $windowMinutes * 60;
        $durationSeconds = $durationMinutes * 60;
        $reportFromAt = $reportFrom->getTimestamp();
        $moment = static fn (int $at): CarbonInterface => $from->copy()->setTimestamp($at);

        // A true fixed-size circular buffer rather than an array plus
        // array_shift(): shift reindexes the whole array on every row, which
        // is O(threshold) per row and turns a rule with a high `count` into
        // real CPU on a busy address. Writing at `$seen % $threshold` and
        // reading the oldest from the same index after the increment is O(1)
        // and allocates exactly once.
        $recent = array_fill(0, $threshold, 0);
        $seen = 0;

        $blockedUntil = null;
        // The next moment the engine would evaluate this address: the row
        // that just reached the threshold, or the tick after a held-back
        // crossing. Null when nothing is pending.
        $evaluateAt = null;
        $blocks = 0;
        $warnings = 0;
        $firstAt = null;
        $lastAt = null;

        // The guard's user count at each tick, from this address's signed-in
        // rows read once in time order and slid along with the ticks, which
        // only move forward. A query per tick cost one per simulated minute
        // for as long as an address kept looking shared — ten thousand a week
        // for one busy office gateway. Holds one window of rows at a time.
        $signedIn = null;
        $inWindow = new \SplQueue;
        $users = [];
        $usersAt = function (int $tick) use (&$signedIn, $inWindow, &$users, $table, $ip, $to, $windowSeconds, $moment): int {
            $signedIn ??= $this->stream(
                DB::table($table)->whereNotNull('user_id'), $ip, $moment($tick - $windowSeconds), $to, ['user_id'],
            );

            for (; $signedIn->valid(); $signedIn->next()) {
                $row = $signedIn->current();
                $at = Carbon::parse($row->occurred_at)->getTimestamp();

                if ($at > $tick) {
                    break;
                }

                $inWindow->enqueue([$at, $row->user_id]);
                $users[$row->user_id] = ($users[$row->user_id] ?? 0) + 1;
            }

            while (! $inWindow->isEmpty() && $inWindow->bottom()[0] < $tick - $windowSeconds) {
                [, $user] = $inWindow->dequeue();

                if (--$users[$user] === 0) {
                    unset($users[$user]);
                }
            }

            return count($users);
        };

        // A trailing null, so the evaluations still pending after the last
        // row — a held-back address re-checked until its window drains —
        // run through the same loop as the ones between rows.
        $rows = (function () use ($table, $level, $messageContains, $ip, $from, $to): \Generator {
            foreach ($this->stream($this->matching($table, $level, $messageContains), $ip, $from, $to) as $row) {
                yield Carbon::parse($row->occurred_at);
            }

            yield null;
        })();

        foreach ($rows as $occurredAt) {
            $at = $occurredAt?->getTimestamp() ?? $to->getTimestamp();

            // Evaluate before this row joins the buffer: a tick earlier than
            // it could not have seen it.
            while ($evaluateAt !== null && $evaluateAt <= $at) {
                $tick = $evaluateAt;
                $evaluateAt = null;

                // Still crossing? The oldest of the last $threshold rows sits
                // at this index, and every one of them must be inside the
                // window ending here.
                if (($tick - $recent[$seen % $threshold]) > $windowSeconds) {
                    break;
                }

                $shared = $sharedIpThreshold > 0 && $usersAt($tick) >= $sharedIpThreshold;

                if ($shared) {
                    $evaluateAt = $tick + self::TICK_SECONDS;
                } else {
                    $blockedUntil = $tick + $durationSeconds;
                }

                // The crossing is real either way — it is what sets the block
                // clock above, so a pre-period burst still suppresses a
                // duplicate report just inside the period, exactly as the
                // engine's own live block would have.
                if ($tick >= $reportFromAt) {
                    $shared ? $warnings++ : $blocks++;
                    $firstAt ??= $tick;
                    $lastAt = $tick;
                }
            }

            if ($occurredAt === null) {
                break;
            }

            $recent[$seen % $threshold] = $at;
            $seen++;

            // Still serving the block the previous crossing earned. The
            // engine skips an address it has already blocked, so a burst
            // that runs for an hour is one block, not one per tick. In warn
            // mode it skips one it has already reported, for the same span
            // — see AutoBlockService::holdDecision() — so this answers for a
            // dry run too.
            if ($blockedUntil !== null && $at < $blockedUntil) {
                continue;
            }

            // `??=`: a held-back address waits for its next tick rather than
            // being judged again at every row, which is what the engine does
            // and what keeps the user count to one a minute.
            if ($seen >= $threshold) {
                $evaluateAt ??= $at;
            }
        }

        return [
            'blocks'   => $blocks,
            'warnings' => $warnings,
            'span'     => $firstAt === null || $lastAt === null ? null : [$moment($firstAt), $moment($lastAt)],
        ];
    }

    /**
     * One address's rows from `$query`, oldest first, a page at a time.
     *
     * Keyset rather than `offset`, and on `(occurred_at, id)` rather than
     * `occurred_at` alone: log rows share a timestamp constantly — a burst
     * is the entire subject of this command — and a keyset on a non-unique
     * column either repeats rows or skips them at every page boundary. `id`
     * is a ULID, so it breaks the tie in insertion order and the pair is
     * unique.
     *
     * @param  list<string>  $columns
     * @return \Generator<int, \stdClass>
     */
    private function stream(
        Builder $query,
        string $ip,
        CarbonInterface $from,
        CarbonInterface $to,
        array $columns = [],
    ): \Generator {
        $lastAt = null;
        $lastId = null;

        while (true) {
            $page = (clone $query)
                ->where('ip_address', $ip)
                ->where('occurred_at', '>=', $from)
                ->where('occurred_at', '<=', $to)
                ->orderBy('occurred_at')
                ->orderBy('id')
                ->limit(self::CHUNK);

            if ($lastAt !== null) {
                $page->where(function (Builder $q) use ($lastAt, $lastId): void {
                    $q->where('occurred_at', '>', $lastAt)
                        ->orWhere(fn (Builder $tie): Builder => $tie
                            ->where('occurred_at', '=', $lastAt)
                            ->where('id', '>', $lastId));
                });
            }

            $rows = $page->get(['id', 'occurred_at', ...$columns]);

            if ($rows->isEmpty()) {
                return;
            }

            yield from $rows;

            $last = $rows->last();
            $lastAt = $last->occurred_at;
            $lastId = $last->id;

            if ($rows->count() < self::CHUNK) {
                return;
            }
        }
    }

    /**
     * Distinct signed-in users one address showed between two moments.
     *
     * Unfiltered by the rule, exactly as the live guard counts it: the
     * question is how many people a block would hit, not how many of them
     * tripped it. `count(distinct ...)` skips NULL, so anonymous rows count
     * for nobody.
     */
    private function distinctUsers(string $table, string $ip, CarbonInterface $from, CarbonInterface $to): int
    {
        return (int) DB::table($table)
            ->where('ip_address', $ip)
            ->whereNotNull('user_id')
            ->where('occurred_at', '>=', $from)
            ->where('occurred_at', '<=', $to)
            ->distinct()
            ->count('user_id');
    }

    /** Rows from one address that carried a signed-in user, optionally rule-filtered. */
    private function authenticatedRows(
        string $table,
        string $ip,
        CarbonInterface $from,
        CarbonInterface $to,
        ?string $level,
        ?string $messageContains,
    ): int {
        return $this->matching($table, $level, $messageContains)
            ->where('ip_address', $ip)
            ->whereNotNull('user_id')
            ->where('occurred_at', '>=', $from)
            ->where('occurred_at', '<=', $to)
            ->count();
    }

    /**
     * The rule's own filters, applied identically everywhere they are needed.
     *
     * Same two clauses as `AutoBlockService::applyRule()`, in the same order,
     * including the `like` — so the simulation and the engine agree about
     * case sensitivity, which is the collation's business and not PHP's.
     * Matching in PHP instead would quietly diverge on any database whose
     * collation is case-insensitive, which is MySQL's default.
     */
    private function matching(string $table, ?string $level, ?string $messageContains): Builder
    {
        $query = DB::table($table);

        if ($level !== null) {
            $query->where('level', $level);
        }

        if ($messageContains !== null) {
            $query->where('message', 'like', '%'.$messageContains.'%');
        }

        return $query;
    }

    /**
     * A rule's optional string setting, or null when it isn't one.
     *
     * The emptiness test is PHP truthiness, not `!== ''`, because
     * `AutoBlockService::applyRule()` gates its two clauses on `if ($level)`
     * and `if ($messageContains)`. Under that, the string `"0"` is falsy and
     * the filter is simply unset — so a `!== ''` test here would apply a
     * filter the engine ignores, and the simulation would report a different
     * offender set from the one the rule actually produces. Nobody writes
     * `level: "0"`, but the claim this class makes is parity, and parity
     * that holds "except for one input" is the kind that gets found later by
     * someone trusting the report.
     */
    private function stringOrNull(mixed $value): ?string
    {
        return is_string($value) && $value !== '' && $value !== '0' ? $value : null;
    }

    /** The log table, resolved the way AutoBlockService resolves it. */
    public function table(): string
    {
        return (string) config('logscope.table', 'log_entries');
    }
}
