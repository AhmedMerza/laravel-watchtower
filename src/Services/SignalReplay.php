<?php

declare(strict_types=1);

namespace Watchtower\Services;

use Carbon\CarbonInterface;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use Watchtower\Support\IpRange;
use Watchtower\Support\KeysetStream;
use Watchtower\Support\SignalLog;

/**
 * Replays a real-time detector over the signal log (#177), at whatever
 * count, window and shared-IP threshold it is handed — the question the
 * observed would-have-blocked lines (#123) can't answer.
 *
 * It mirrors the live engine step for step, so a replay at the settings that
 * were in force reproduces the lines the engine wrote:
 *
 * - the window is fixed from its first hit (HitWindow::hit()), and the users
 *   set from its first signed-in hit (HitWindow::recordUser());
 * - the counter restarts at every decided crossing (HitWindow::close());
 * - a decision reported rather than enforced is held for the block duration,
 *   on block mode's terms (AutoBlockService::heldAs()), during which the
 *   address keeps counting but isn't decided again — except the shared-IP
 *   guard, which the engine re-measures every time;
 * - a block takes the address out of play: the engine counts nothing from a
 *   blocked address, so neither does this.
 *
 * Each detector is replayed alone. A block one detector would have written
 * stops every detector counting the address live; here the others go on.
 *
 * Writes nothing, like RuleSimulator, and for its reason.
 */
final class SignalReplay
{
    /**
     * Addresses held before the first sweep of state that can no longer
     * matter. Each sweep sets the next at twice what survived, so a flood of
     * live addresses costs amortised constant time per row, not a sweep of
     * all of them every so many rows.
     */
    private const SWEEP_AT = 1000;

    /**
     * Each crossing, grouped by the address that made it — the same shape
     * DetectorHistory::observed() gives an offender, so the report renders
     * either.
     *
     * @return list<array{ip: string, reports: int, first_at: string, last_at: string, user_ids: list<string>, outcomes: array<string, int>}>
     */
    public function replay(
        string $detector,
        int $threshold,
        int $windowMinutes,
        int $sharedIpThreshold,
        string $mode,
        string $scope,
        int $durationMinutes,
        CarbonInterface $from,
        CarbonInterface $to,
    ): array {
        $window = max(1, $windowMinutes) * 60;
        $threshold = max(1, $threshold);
        $duration = max(1, $durationMinutes) * 60;

        /** @var array<string, array{ends: int, hits: int, users_end: int, users: array<string, true>, out: int, hold: int, reason: string}> $state */
        $state = [];
        $offenders = [];
        $sweepAt = self::SWEEP_AT;

        $query = DB::table(SignalLog::TABLE)->where('detector', $detector);

        foreach (KeysetStream::rows($query, $from, $to, ['ip', 'user_id']) as $row) {
            $at = Carbon::parse($row->occurred_at)->getTimestamp();
            $ip = (string) $row->ip;
            $counted = IpRange::blockTarget($ip) ?? $ip;

            if (count($state) >= $sweepAt) {
                $state = array_filter($state, static fn (array $s): bool => max($s['ends'], $s['users_end'], $s['out'], $s['hold']) > $at);
                $sweepAt = max(self::SWEEP_AT, 2 * count($state));
            }

            $s = $state[$counted] ?? ['ends' => 0, 'hits' => 0, 'users_end' => 0, 'users' => [], 'out' => 0, 'hold' => 0, 'reason' => ''];

            if ($at < $s['out']) {
                continue;
            }

            if ($at >= $s['ends']) {
                $s['ends'] = $at + $window;
                $s['hits'] = 0;
            }

            $s['hits']++;

            if ($row->user_id !== null) {
                if ($at >= $s['users_end']) {
                    $s['users_end'] = $at + $window;
                    $s['users'] = [];
                }

                $s['users'][(string) $row->user_id] = true;
            }

            $held = $at < $s['hold'] && AutoBlockService::holdStillSpeaksFor($s['reason'], $ip);

            if ($s['hits'] >= $threshold && ! $held) {
                $users = $at < $s['users_end'] ? array_keys($s['users']) : [];
                $s['ends'] = 0;
                $s['users_end'] = 0;
                $s['users'] = [];

                $verdict = AutoBlockService::inBlockMode($ip, $scope, count($users), $sharedIpThreshold);

                $heldBy = $mode === 'warn' ? AutoBlockService::heldAs('warn mode', $verdict) : $verdict;

                if ($mode !== 'warn' && ($verdict === 'blocked' || $verdict === 'blocked_in_scope')) {
                    $s['out'] = $at + $duration;
                } elseif (AutoBlockService::opensHold($heldBy)) {
                    [$s['hold'], $s['reason']] = [$at + $duration, $heldBy];
                }

                $o = $offenders[$ip] ?? ['ip' => $ip, 'reports' => 0, 'first_at' => $at, 'last_at' => $at, 'user_ids' => [], 'outcomes' => []];
                $o['reports']++;
                $o['last_at'] = $at;
                $o['outcomes'][$verdict] = ($o['outcomes'][$verdict] ?? 0) + 1;

                foreach ($users as $id) {
                    $o['user_ids'][(string) $id] = true;
                }

                $offenders[$ip] = $o;
            }

            $state[$counted] = $s;
        }

        $list = array_map(static fn (array $o): array => [
            ...$o,
            'first_at' => Carbon::createFromTimestamp($o['first_at'])->toIso8601String(),
            'last_at'  => Carbon::createFromTimestamp($o['last_at'])->toIso8601String(),
            'user_ids' => array_map('strval', array_keys($o['user_ids'])),
        ], array_values($offenders));

        usort($list, static fn (array $a, array $b): int => $b['reports'] <=> $a['reports'] ?: strcmp($a['ip'], $b['ip']));

        return $list;
    }

    /** When the oldest signal still in the log was counted, or null when it's empty. */
    public function oldest(): ?CarbonInterface
    {
        $at = DB::table(SignalLog::TABLE)->min('occurred_at');

        return $at === null ? null : Carbon::parse($at);
    }

    /** Whether the log holds any signal in [from, to]. */
    public function covers(CarbonInterface $from, CarbonInterface $to): bool
    {
        return DB::table(SignalLog::TABLE)
            ->where('occurred_at', '>=', $from)
            ->where('occurred_at', '<=', $to)
            ->exists();
    }
}
