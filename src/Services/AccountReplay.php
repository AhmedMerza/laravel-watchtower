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

    /** Account ids listed per subject; the rest are only counted. */
    private const MAX_USER_IDS = 100;

    /**
     * Each crossing, grouped by its subject.
     *
     * @return list<array{subject: string, guard: ?string, crossings: int, first_at: string, last_at: string, members: int, target_users: int, target_user_ids: list<string>}>
     */
    public function replay(string $rule, int $threshold, int $windowMinutes, int $ipv4Prefix, CarbonInterface $from, CarbonInterface $to): array
    {
        $seconds = max(1, $windowMinutes) * 60;
        $threshold = AccountTargeting::clampCount($threshold);

        /** @var array<string, array{expires: int, members: array<string, ?string>}> $windows */
        $windows = [];
        $subjects = [];
        $sweepAt = self::SWEEP_AT;

        $query = DB::table(SignalLog::TABLE)->where('detector', 'failed_logins')->whereNotNull('target_hash');

        foreach (KeysetStream::rows($query, $from, $to, ['ip', 'target_hash', 'target_user_id', 'guard']) as $row) {
            $at = Carbon::parse($row->occurred_at)->getTimestamp();
            $guard = $row->guard === null ? null : (string) $row->guard;
            $userId = $row->target_user_id === null ? null : (string) $row->target_user_id;
            $keys = AccountTargeting::keys($rule, (string) $row->ip, (string) $row->target_hash, $userId, $guard, $ipv4Prefix);

            if ($keys === null) {
                continue;
            }

            if (count($windows) >= $sweepAt) {
                $windows = array_filter($windows, static fn (array $w): bool => $w['expires'] > $at);
                $sweepAt = max(self::SWEEP_AT, 2 * count($windows));
            }

            [$subject, $member] = $keys;

            [$window, $crossed] = AccountTargeting::step($windows[$subject] ?? null, $member, $userId, $at, $seconds, $threshold);

            if ($window !== null) {
                $windows[$subject] = $window;

                continue;
            }

            unset($windows[$subject]);

            $s = $subjects[$subject] ?? [
                'subject'         => $rule === 'one_account' ? (string) $userId : $subject,
                'guard'           => $rule === 'one_account' ? $guard : null,
                'crossings'       => 0,
                'first_at'        => $at,
                'last_at'         => $at,
                'members'         => [],
                'target_users'    => [],
            ];
            $s['crossings']++;
            $s['last_at'] = $at;

            // Only counted, so a short binary digest stands in for each: a
            // subnet sprayed for days can cross with a million accounts.
            foreach ((array) $crossed as $crossedMember => $crossedUser) {
                $s['members'][hash('xxh64', (string) $crossedMember, true)] = true;

                if ($crossedUser !== null) {
                    $s['target_users'][hash('xxh64', $crossedUser, true)] ??= count($s['target_users']) < self::MAX_USER_IDS ? $crossedUser : null;
                }
            }

            $subjects[$subject] = $s;
        }

        $list = array_map(static fn (array $s): array => [
            ...$s,
            'first_at'        => Carbon::createFromTimestamp($s['first_at'])->toIso8601String(),
            'last_at'         => Carbon::createFromTimestamp($s['last_at'])->toIso8601String(),
            'members'         => count($s['members']),
            'target_users'    => count($s['target_users']),
            'target_user_ids' => array_values(array_filter($s['target_users'], static fn (?string $id): bool => $id !== null)),
        ], array_values($subjects));

        usort($list, static fn (array $a, array $b): int => $b['crossings'] <=> $a['crossings'] ?: strcmp($a['subject'], $b['subject']));

        return $list;
    }

    /**
     * Whether the period holds a failed login with an account hash — without
     * one the replay has nothing to read, and "no crossings" would pass for
     * a clean result.
     */
    public function covers(CarbonInterface $from, CarbonInterface $to, ?string $rule = null): bool
    {
        return DB::table(SignalLog::TABLE)
            ->where('detector', 'failed_logins')
            ->whereNotNull('target_hash')
            // one_account reads only attempts at an existing account.
            ->when($rule === 'one_account', static fn ($query) => $query->whereNotNull('target_user_id'))
            ->where('occurred_at', '>=', $from)
            ->where('occurred_at', '<=', $to)
            ->exists();
    }
}
