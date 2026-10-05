<?php

declare(strict_types=1);

namespace Watchtower\Services;

use Carbon\CarbonInterface;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;

/**
 * What the real-time detectors reported while they ran in `warn` mode.
 *
 * The log rules can be replayed because they read log lines, and LogScope
 * kept those. The detectors can't: they count failed logins, lockouts,
 * response statuses, request paths and User-Agents as they happen, and
 * LogScope stores log lines rather than requests — there is no status
 * column, and a request that logged nothing left no row at all (#123).
 *
 * What it DOES hold is every would-have-blocked line the live detectors
 * wrote. Those are not a simulation: the real detector, at the real
 * settings, on real traffic, decided each one. So this reads them back and
 * says so — observed, not replayed — instead of approximating a replay from
 * the few requests that happened to log something.
 *
 * Read-only, like RuleSimulator, and for the same reason.
 */
class DetectorHistory
{
    /** The outcome of a warn-mode line written before v0.11.0 recorded one. */
    public const NOT_RECORDED = 'not recorded';

    /** Rows read per page. */
    private const CHUNK = 1000;

    /**
     * Offenders per detector, busiest first, plus how many matching rows
     * had a context that didn't decode — LogScope truncates large ones, and
     * a report that silently dropped them would undercount.
     *
     * @return array{detectors: array<string, list<array<string, mixed>>>, unreadable: int}
     */
    public function observed(string $table, CarbonInterface $from, CarbonInterface $to): array
    {
        /** @var array<string, array<string, array{ip: string, reports: int, first_at: string, last_at: string, user_ids: array<string, true>, outcomes: array<string, int>}>> $byDetector */
        $byDetector = [];
        $unreadable = 0;

        // (level, occurred_at) is indexed in LogScope's schema; the message
        // match then only runs over the warnings in range.
        $rows = DB::table($table)
            ->select(['id', 'context', 'occurred_at'])
            ->where('level', 'warning')
            ->where('message', AutoBlockService::WOULD_HAVE_BLOCKED_MESSAGE)
            ->whereBetween('occurred_at', [$from, $to])
            ->lazyById(self::CHUNK, 'id');

        foreach ($rows as $row) {
            $context = is_string($row->context) ? json_decode($row->context, true) : null;

            if (! is_array($context)) {
                $unreadable++;

                continue;
            }

            // The log rules write the same line keyed by 'rule'; those are
            // replayed properly by RuleSimulator and don't belong here.
            if (! is_string($context['detector'] ?? null) || ! is_string($context['ip'] ?? null)) {
                continue;
            }

            $detector = $context['detector'];
            $ip = $context['ip'];
            $at = Carbon::parse($row->occurred_at)->toIso8601String();

            $offender = $byDetector[$detector][$ip] ?? [
                'ip'       => $ip,
                'reports'  => 0,
                'first_at' => $at,
                'last_at'  => $at,
                'user_ids' => [],
                'outcomes' => [],
            ];

            $offender['reports']++;
            $offender['first_at'] = min($offender['first_at'], $at);
            $offender['last_at'] = max($offender['last_at'], $at);

            foreach ((array) ($context['user_ids'] ?? []) as $id) {
                $offender['user_ids'][(string) $id] = true;
            }

            $outcome = self::outcome($context);
            $offender['outcomes'][$outcome] = ($offender['outcomes'][$outcome] ?? 0) + 1;

            $byDetector[$detector][$ip] = $offender;
        }

        $result = [];

        foreach ($byDetector as $detector => $offenders) {
            $list = array_map(static function (array $o): array {
                $o['user_ids'] = array_keys($o['user_ids']);

                return $o;
            }, array_values($offenders));

            usort($list, static fn (array $a, array $b): int => $b['reports'] <=> $a['reports'] ?: strcmp($a['ip'], $b['ip']));

            $result[$detector] = $list;
        }

        ksort($result);

        return ['detectors' => $result, 'unreadable' => $unreadable];
    }

    /**
     * What block mode would have done, when the line came from warn mode —
     * the engine records that answer as `in_block_mode` (#121). Otherwise the
     * line is block mode's own hold-back, and its reason is the outcome.
     *
     * A warn-mode line from before v0.11.0 has no `in_block_mode`, and that
     * is reported as not recorded rather than guessed — guessing 'blocked'
     * would tell an operator that arming locks a customer out when the line
     * never said so.
     *
     * @param  array<string, mixed>  $context
     */
    private static function outcome(array $context): string
    {
        $because = (string) ($context['not_blocked_because'] ?? 'unknown');

        if ($because === 'warn mode') {
            return (string) ($context['in_block_mode'] ?? self::NOT_RECORDED);
        }

        return 'held: '.$because;
    }
}
