<?php

declare(strict_types=1);

namespace Watchtower\Services;

use Carbon\CarbonInterface;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use Watchtower\Support\KeysetStream;
use Watchtower\Support\SignalLog;

/**
 * Replays an account-targeting rule (#180) over the failed logins in the
 * signal log, at whatever count and window it is handed — so a threshold is
 * proven on real traffic before anyone listens for AccountTargeted.
 *
 * Every row goes through AccountTargeting::keys() and ::step(), the code the
 * live count runs, so a replay at the settings in force reproduces the
 * events that fired. It sees what failed_logins counted: a login from an
 * address failed_logins skipped (blocked where it aims) is in neither the
 * log nor the replay, while the live count saw it.
 *
 * Writes nothing, like SignalReplay, and for its reason.
 */
final class AccountReplay
{
    /** See SignalReplay::SWEEP_AT. */
    private const SWEEP_AT = 1000;

    /**
     * Each crossing, grouped by its subject.
     *
     * @return list<array{subject: string, guard: ?string, crossings: int, first_at: string, last_at: string, members: int, target_user_ids: list<string>}>
     */
    public function replay(string $rule, int $threshold, int $windowMinutes, int $ipv4Prefix, CarbonInterface $from, CarbonInterface $to): array
    {
        $seconds = max(1, $windowMinutes) * 60;
        $threshold = max(2, $threshold);

        /** @var array<string, array{expires: int, members: array<string, ?string>}> $windows */
        $windows = [];
        $subjects = [];
        $sweepAt = self::SWEEP_AT;

        $query = DB::table(SignalLog::TABLE)->where('detector', 'failed_logins')->whereNotNull('target_hash');

        foreach (KeysetStream::rows($query, $from, $to, ['ip', 'target_hash', 'target_user_id', 'guard']) as $row) {
            $at = Carbon::parse($row->occurred_at)->getTimestamp();
            $guard = $row->guard === null ? null : (string) $row->guard;
            $keys = AccountTargeting::keys($rule, (string) $row->ip, (string) $row->target_hash, $guard, $ipv4Prefix);

            if ($keys === null) {
                continue;
            }

            if (count($windows) >= $sweepAt) {
                $windows = array_filter($windows, static fn (array $w): bool => $w['expires'] > $at);
                $sweepAt = max(self::SWEEP_AT, 2 * count($windows));
            }

            [$subject, $member] = $keys;
            $userId = $row->target_user_id === null ? null : (string) $row->target_user_id;

            [$window, $crossed] = AccountTargeting::step($windows[$subject] ?? null, $member, $userId, $at, $seconds, $threshold);

            if ($window !== null) {
                $windows[$subject] = $window;

                continue;
            }

            unset($windows[$subject]);

            $s = $subjects[$subject] ?? [
                'subject'         => $rule === 'one_account' ? (string) $row->target_hash : $subject,
                'guard'           => $rule === 'one_account' ? $guard : null,
                'crossings'       => 0,
                'first_at'        => $at,
                'last_at'         => $at,
                'members'         => [],
                'target_user_ids' => [],
            ];
            $s['crossings']++;
            $s['last_at'] = $at;

            foreach ((array) $crossed as $crossedMember => $crossedUser) {
                $s['members']["m:{$crossedMember}"] = true;

                if ($crossedUser !== null) {
                    $s['target_user_ids']["u:{$crossedUser}"] = true;
                }
            }

            $subjects[$subject] = $s;
        }

        $list = array_map(static fn (array $s): array => [
            ...$s,
            'first_at'        => Carbon::createFromTimestamp($s['first_at'])->toIso8601String(),
            'last_at'         => Carbon::createFromTimestamp($s['last_at'])->toIso8601String(),
            'members'         => count($s['members']),
            'target_user_ids' => array_map(static fn ($key): string => substr((string) $key, 2), array_keys($s['target_user_ids'])),
        ], array_values($subjects));

        usort($list, static fn (array $a, array $b): int => $b['crossings'] <=> $a['crossings'] ?: strcmp($a['subject'], $b['subject']));

        return $list;
    }
}
