<?php

declare(strict_types=1);

namespace Watchtower\Services;

use Carbon\CarbonInterface;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use Watchtower\Listeners\DetectAuthFailures;
use Watchtower\Support\KeysetStream;

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

    /**
     * Offenders per detector, busiest first, plus how many matching rows
     * couldn't be used — a context LogScope cut short, or one no detector
     * wrote — since a report that silently dropped them would undercount.
     *
     * @return array{detectors: array<string, list<array<string, mixed>>>, unreadable: int}
     */
    public function observed(string $table, CarbonInterface $from, CarbonInterface $to): array
    {
        /** @var array<string, array<string, array{ip: string, reports: int, first_at: string, last_at: string, user_ids: array<string, true>, outcomes: array<string, int>}>> $byDetector */
        $byDetector = [];
        $unreadable = 0;

        // Only names the engine could have run: the log table is shared, and
        // anything can log this message with a context of its choosing.
        $known = array_keys((array) config('watchtower.auto_block.detectors', []));

        // The (level, occurred_at) index serves the range; the message match
        // then only runs over the warnings inside it.
        $query = DB::table($table)
            ->where('level', 'warning')
            ->where('message', AutoBlockService::WOULD_HAVE_BLOCKED_MESSAGE);

        foreach (KeysetStream::rows($query, $from, $to, ['context']) as $row) {
            $context = is_string($row->context) ? json_decode($row->context, true) : null;

            // The log rules write the same line keyed by 'rule'; those are
            // replayed properly by RuleSimulator and don't belong here.
            if (is_array($context) && ! array_key_exists('detector', $context)) {
                continue;
            }

            if (! is_array($context)
                || ! in_array($context['detector'], $known, true)
                || ! is_string($context['ip'] ?? null)
                || filter_var($context['ip'], FILTER_VALIDATE_IP) === false) {
                $unreadable++;

                continue;
            }

            $detector = $context['detector'];
            $ip = $context['ip'];
            // Parsed once per address below rather than once per row.
            $at = (string) $row->occurred_at;

            $offender = $byDetector[$detector][$ip] ?? [
                'ip'       => $ip,
                'reports'  => 0,
                'first_at' => $at,
                'last_at'  => $at,
                'user_ids' => [],
                'outcomes' => [],
            ];

            // Rows arrive oldest first, so the first one seen stays first.
            $offender['reports']++;
            $offender['last_at'] = $at;

            foreach ((array) ($context['user_ids'] ?? []) as $id) {
                if (is_int($id) || is_string($id)) {
                    $offender['user_ids'][(string) $id] = true;
                }
            }

            $outcome = self::outcome($context);
            $offender['outcomes'][$outcome] = ($offender['outcomes'][$outcome] ?? 0) + 1;

            $byDetector[$detector][$ip] = $offender;
        }

        $result = [];

        foreach ($byDetector as $detector => $offenders) {
            // The auth detectors' lines name no users, so `user_ids` is empty
            // whoever was behind the address. Who LogScope saw signed in from
            // it is the number that says whether a block would hit customers.
            $userless = in_array($detector, DetectAuthFailures::DETECTORS, true);

            $list = array_map(static function (array $o) use ($userless, $table, $from, $to): array {
                $o['user_ids'] = array_map('strval', array_keys($o['user_ids']));
                $o['first_at'] = Carbon::parse($o['first_at'])->toIso8601String();
                $o['last_at'] = Carbon::parse($o['last_at'])->toIso8601String();

                if ($userless) {
                    $o['logscope_users'] = RuleSimulator::distinctUsers($table, $o['ip'], $from, $to);
                }

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
        $because = is_string($context['not_blocked_because'] ?? null) ? $context['not_blocked_because'] : 'unknown';

        if ($because === 'warn mode') {
            return is_string($context['in_block_mode'] ?? null) ? $context['in_block_mode'] : self::NOT_RECORDED;
        }

        return 'held: '.$because;
    }
}
