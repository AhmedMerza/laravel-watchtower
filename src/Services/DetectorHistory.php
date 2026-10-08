<?php

declare(strict_types=1);

namespace Watchtower\Services;

use Carbon\CarbonInterface;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
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
 * Since #150 a real auto-block writes its own line too, so block mode's
 * blocks are read back beside its hold-backs (#154): one report then says
 * what was blocked, for how long, and what was held back.
 *
 * Read-only, like RuleSimulator, and for the same reason.
 */
class DetectorHistory
{
    /** The outcome of a warn-mode line written before v0.11.0 recorded one. */
    public const NOT_RECORDED = 'not recorded';

    /**
     * Offenders and real blocks per detector, busiest first, plus how many
     * matching rows couldn't be used — a context LogScope cut short, or one
     * no detector wrote — since a report that silently dropped them would
     * undercount.
     *
     * @return array{detectors: array<string, list<array<string, mixed>>>, blocks: array<string, list<array<string, mixed>>>, unreadable: int}
     */
    public function observed(string $table, CarbonInterface $from, CarbonInterface $to): array
    {
        /** @var array<string, array<string, array{ip: string, reports: int, first_at: string, last_at: string, user_ids: array<string, true>, outcomes: array<string, int>}>> $byDetector */
        $byDetector = [];
        /** @var array<string, array<string, array{ip: string, blocks: int, first_at: string, last_at: string, minutes: int, expires_at: mixed, scopes: array<string, true>, user_ids: array<string, true>}>> $blocksByDetector */
        $blocksByDetector = [];
        $unreadable = 0;

        // Only names the engine could have run: the log table is shared, and
        // anything can log this message with a context of its choosing.
        $known = array_keys((array) config('watchtower.auto_block.detectors', []));

        // The (level, occurred_at) index serves the range; the message match
        // then only runs over the warnings inside it.
        $query = DB::table($table)
            ->where('level', 'warning')
            ->whereIn('message', [AutoBlockService::WOULD_HAVE_BLOCKED_MESSAGE, AutoBlockService::AUTO_BLOCKED_MESSAGE]);

        foreach (KeysetStream::rows($query, $from, $to, ['context', 'message']) as $row) {
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

            if ($row->message === AutoBlockService::AUTO_BLOCKED_MESSAGE) {
                $block = $blocksByDetector[$detector][$ip] ?? [
                    'ip'         => $ip,
                    'blocks'     => 0,
                    'first_at'   => $at,
                    'last_at'    => $at,
                    'minutes'    => 0,
                    'expires_at' => null,
                    'scopes'     => [],
                    'user_ids'   => [],
                ];

                $block['blocks']++;
                $block['last_at'] = $at;
                // A negative length is forged, and would cancel real minutes.
                $duration = $context['duration_minutes'] ?? null;
                $block['minutes'] += is_int($duration) && $duration >= 0 ? $duration : 0;
                // The latest block's expiry, unusable or not: it is the one
                // that could still be on, and an older one in its place would
                // be a confident wrong answer. Parsed once per address below.
                $block['expires_at'] = $context['expires_at'] ?? null;
                $block['scopes'][is_string($context['scope'] ?? null) ? $context['scope'] : ''] = true;

                foreach ((array) ($context['user_ids'] ?? []) as $id) {
                    if (is_int($id) || is_string($id)) {
                        $block['user_ids'][(string) $id] = true;
                    }
                }

                $blocksByDetector[$detector][$ip] = $block;

                continue;
            }

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

        // The auth detectors' lines name no users, so `user_ids` is empty
        // whoever was behind the address. Who LogScope saw signed in from it
        // is the number that says whether a block would hit customers.
        // One lookup per address, however many of them flagged it.
        $userless = array_intersect_key($byDetector, array_flip(AutoBlockService::USERLESS_DETECTORS));
        $ips = [];

        foreach ($userless as $offenders) {
            $ips += $offenders;
        }

        $usersAt = self::usersAt($table, array_map('strval', array_keys($ips)), $from, $to);

        $result = [];

        foreach ($byDetector as $detector => $offenders) {
            $countUsers = isset($userless[$detector]);

            $list = array_map(static function (array $o) use ($countUsers, $usersAt): array {
                $o['user_ids'] = array_map('strval', array_keys($o['user_ids']));
                $o['first_at'] = Carbon::parse($o['first_at'])->toIso8601String();
                $o['last_at'] = Carbon::parse($o['last_at'])->toIso8601String();

                if ($countUsers) {
                    $o['logscope_users'] = $usersAt[$o['ip']] ?? 0;
                }

                return $o;
            }, array_values($offenders));

            usort($list, static fn (array $a, array $b): int => $b['reports'] <=> $a['reports'] ?: strcmp($a['ip'], $b['ip']));

            $result[$detector] = $list;
        }

        ksort($result);

        $blocks = [];

        foreach ($blocksByDetector as $detector => $blocked) {
            $list = array_map(static function (array $b): array {
                $b['user_ids'] = array_map('strval', array_keys($b['user_ids']));
                $b['scopes'] = array_map('strval', array_keys($b['scopes']));
                $b['expires_at'] = self::isoOrNull($b['expires_at']);
                $b['first_at'] = Carbon::parse($b['first_at'])->toIso8601String();
                $b['last_at'] = Carbon::parse($b['last_at'])->toIso8601String();

                return $b;
            }, array_values($blocked));

            usort($list, static fn (array $a, array $b): int => $b['blocks'] <=> $a['blocks'] ?: strcmp($a['ip'], $b['ip']));

            $blocks[$detector] = $list;
        }

        ksort($blocks);

        return ['detectors' => $result, 'blocks' => $blocks, 'unreadable' => $unreadable];
    }

    /**
     * Distinct signed-in users LogScope saw from each address, in one grouped
     * query per chunk rather than one per address — a botnet can flag
     * thousands. Unfiltered, like the live guard: the question is who a block
     * would hit. Addresses with none are absent.
     *
     * @param  list<string>  $ips
     * @return array<string, int>
     */
    private static function usersAt(string $table, array $ips, CarbonInterface $from, CarbonInterface $to): array
    {
        $counts = [];

        foreach (array_chunk($ips, 500) as $chunk) {
            $rows = DB::table($table)
                ->whereIn('ip_address', $chunk)
                ->whereNotNull('user_id')
                ->where('occurred_at', '>=', $from)
                ->where('occurred_at', '<=', $to)
                ->groupBy('ip_address')
                ->selectRaw('ip_address, count(distinct user_id) as users')
                ->get();

            foreach ($rows as $row) {
                $counts[(string) $row->ip_address] = (int) $row->users;
            }
        }

        return $counts;
    }

    /**
     * A timestamp read out of the shared log table, normalised, or null when
     * it isn't one — the report prints it, so it must not be arbitrary text.
     */
    private static function isoOrNull(mixed $value): ?string
    {
        if (! is_string($value)) {
            return null;
        }

        try {
            return Carbon::parse($value)->toIso8601String();
        } catch (\Throwable) {
            return null;
        }
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
