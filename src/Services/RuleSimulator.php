<?php

declare(strict_types=1);

namespace Watchtower\Services;

use Carbon\CarbonInterface;
use Illuminate\Database\Query\Builder;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;

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
     *     offenders: list<array{
     *         ip: string,
     *         blocks: int,
     *         first_block_at: string,
     *         last_block_at: string,
     *         distinct_users: int,
     *         users_at_first_block: int,
     *         authenticated_rows_not_matching: int,
     *         held_back_by_shared_ip_guard: bool
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

        $offenders = [];

        foreach ($this->candidates($table, $level, $messageContains, $from, $to, $threshold) as $ip) {
            $blockedAt = $this->replay(
                $table, $level, $messageContains, $ip, $from, $to,
                $windowMinutes, $threshold, $durationMinutes,
            );

            if ($blockedAt === []) {
                continue;
            }

            $first = $blockedAt[0];
            $usersAtFirstBlock = $this->distinctUsers(
                $table, $ip, $first->copy()->subMinutes($windowMinutes), $first,
            );

            $offenders[] = [
                'ip'                   => $ip,
                'blocks'               => count($blockedAt),
                'first_block_at'       => $first->toIso8601String(),
                'last_block_at'        => $blockedAt[count($blockedAt) - 1]->toIso8601String(),
                'distinct_users'       => $this->distinctUsers($table, $ip, $from, $to),
                'users_at_first_block' => $usersAtFirstBlock,

                // The false-positive signal. Authenticated traffic from this
                // address that never matched the rule is, by construction,
                // somebody signed in doing something the rule has no quarrel
                // with — and a block would have taken it away from them.
                'authenticated_rows_not_matching' => $this->authenticatedRows($table, $ip, $from, $to, null, null)
                    - $this->authenticatedRows($table, $ip, $from, $to, $level, $messageContains),

                // Computed against the window the LIVE guard would have read
                // at the moment of the first block, not the period-wide
                // figure — the period-wide count is an upper bound and would
                // predict downgrades that never happen.
                'held_back_by_shared_ip_guard' => $sharedIpThreshold > 0
                    && $usersAtFirstBlock >= $sharedIpThreshold,
            ];
        }

        // Busiest first: the report is read top-down and the address with the
        // most would-be blocks is the one the operator is deciding about.
        usort($offenders, static fn (array $a, array $b): int => $b['blocks'] <=> $a['blocks']
            ?: strcmp($a['ip'], $b['ip']));

        return [
            'rule_index'       => $ruleIndex,
            'mode'             => $mode,
            'level'            => $level,
            'message_contains' => $messageContains,
            'threshold'        => $threshold,
            'window_minutes'   => $windowMinutes,
            'scope'            => $this->stringOrNull($rule['scope'] ?? null),
            'offenders'        => $offenders,
        ];
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
     * moment the engine would have blocked it.
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
     * @return list<CarbonInterface>
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
    ): array {
        $windowSeconds = $windowMinutes * 60;
        $durationSeconds = $durationMinutes * 60;

        /** @var list<int> $recent */
        $recent = [];
        $blockedUntil = null;
        $blockedAt = [];

        foreach ($this->stream($table, $level, $messageContains, $ip, $from, $to) as $occurredAt) {
            $at = $occurredAt->getTimestamp();

            $recent[] = $at;

            if (count($recent) > $threshold) {
                array_shift($recent);
            }

            // Still serving the block the previous crossing earned. The
            // engine skips an address it has already blocked, so a burst
            // that runs for an hour is one block, not one per tick.
            if ($blockedUntil !== null && $at < $blockedUntil) {
                continue;
            }

            if (count($recent) === $threshold && ($at - $recent[0]) <= $windowSeconds) {
                $blockedAt[] = $occurredAt;
                $blockedUntil = $at + $durationSeconds;
            }
        }

        return $blockedAt;
    }

    /**
     * One address's matching rows, oldest first, a page at a time.
     *
     * Keyset rather than `offset`, and on `(occurred_at, id)` rather than
     * `occurred_at` alone: log rows share a timestamp constantly — a burst
     * is the entire subject of this command — and a keyset on a non-unique
     * column either repeats rows or skips them at every page boundary. `id`
     * is a ULID, so it breaks the tie in insertion order and the pair is
     * unique.
     *
     * @return \Generator<int, CarbonInterface>
     */
    private function stream(
        string $table,
        ?string $level,
        ?string $messageContains,
        string $ip,
        CarbonInterface $from,
        CarbonInterface $to,
    ): \Generator {
        $lastAt = null;
        $lastId = null;

        while (true) {
            $query = $this->matching($table, $level, $messageContains)
                ->where('ip_address', $ip)
                ->where('occurred_at', '>=', $from)
                ->where('occurred_at', '<=', $to)
                ->orderBy('occurred_at')
                ->orderBy('id')
                ->limit(self::CHUNK);

            if ($lastAt !== null) {
                $query->where(function (Builder $q) use ($lastAt, $lastId): void {
                    $q->where('occurred_at', '>', $lastAt)
                        ->orWhere(fn (Builder $tie): Builder => $tie
                            ->where('occurred_at', '=', $lastAt)
                            ->where('id', '>', $lastId));
                });
            }

            $rows = $query->get(['id', 'occurred_at']);

            if ($rows->isEmpty()) {
                return;
            }

            foreach ($rows as $row) {
                yield Carbon::parse($row->occurred_at);
            }

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

    private function stringOrNull(mixed $value): ?string
    {
        return is_string($value) && $value !== '' ? $value : null;
    }

    /** The log table, resolved the way AutoBlockService resolves it. */
    public function table(): string
    {
        return (string) config('logscope.table', 'log_entries');
    }
}
