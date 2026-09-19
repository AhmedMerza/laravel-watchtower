<?php

declare(strict_types=1);

namespace Watchtower\Services;

use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;
use Watchtower\Enums\BlockSource;
use Watchtower\Exceptions\NeverAutoBlockException;
use Watchtower\Exceptions\NeverBlockException;
use Watchtower\Support\HitWindow;

class AutoBlockService
{
    /**
     * Valid auto-block modes. Anything else falls back to 'warn', the safe
     * end of the range: a typo in the mode shouldn't start blocking people.
     */
    private const VALID_MODES = ['block', 'warn', 'disabled'];

    /** Distinct signed-in users from one address before a block downgrades. */
    private const DEFAULT_SHARED_IP_USER_THRESHOLD = 3;

    public function __construct(
        private readonly BlacklistService $blacklist,
        private readonly HitWindow $hits,
    ) {}

    /**
     * Count one real-time detector signal against an address, and block it
     * if that crosses the detector's threshold.
     *
     * This is the other half of the engine: run() evaluates log-based rules
     * on a schedule, so it can only see what the app wrote to a log table
     * and only reacts on the next tick. The detectors call here instead, as
     * the signal happens, which is why they work with no log table at all.
     * Both ends share one set of guards — mode, the shared-IP threshold,
     * never_auto_block — so arming a detector can't sidestep a protection
     * that a rule respects.
     *
     * Nothing is written for traffic a detector doesn't match: the caller
     * decides whether this is a signal at all, and only then does an
     * address get a counter.
     *
     * @param  int|string|null  $userId  the signed-in user this signal came
     *                                   from, when there is one, so the
     *                                   shared-IP guard can tell a carrier
     *                                   gateway from one bad actor.
     * @return bool whether the address is blocked now — the scanner-path
     *              detector answers the request itself when it is.
     */
    public function record(string $detector, string $ip, int|string|null $userId = null): bool
    {
        if (! config('watchtower.auto_block.enabled', false)) {
            return false;
        }

        $settings = (array) config("watchtower.auto_block.detectors.{$detector}", []);

        if (! ($settings['enabled'] ?? false)) {
            return false;
        }

        $mode = $this->resolveRuleMode(
            $settings,
            $this->normaliseMode(config('watchtower.auto_block.mode', 'warn')),
        );

        if ($mode === 'disabled') {
            return false;
        }

        // Already blocked: don't count, and don't block again. A blocked
        // scanner keeps knocking, and re-blocking on every knock would
        // restart the duration each time and never let it lapse.
        if ($this->blacklist->isBlocked($ip)) {
            return true;
        }

        $windowMinutes = max(1, (int) ($settings['window_minutes'] ?? 5));
        $windowSeconds = $windowMinutes * 60;
        $threshold = max(1, (int) ($settings['count'] ?? 1));

        // Count against what a block would actually cover, not the address
        // the request came from. A block widens a single IPv6 address to its
        // prefix because the client can hop anywhere inside it — and a
        // counter keyed on the bare address would hand it a fresh budget on
        // every hop, so an IPv6 attacker could outlast any threshold by
        // moving within the /64 that a block would have caught anyway.
        $counted = $this->blacklist->normalizeTarget($ip);

        $hits = $this->hits->hit($detector, $counted, $windowSeconds);

        if ($userId !== null) {
            $this->hits->recordUser($detector, $counted, $userId, $windowSeconds);
        }

        if ($hits < $threshold) {
            return false;
        }

        return $this->blockDetected($detector, $ip, $counted, $mode, $hits, $threshold, $windowMinutes);
    }

    /**
     * A detector reached its threshold: apply the same guards a rule gets,
     * then block or report the near miss.
     */
    private function blockDetected(
        string $detector,
        string $ip,
        string $counted,
        string $mode,
        int $hits,
        int $threshold,
        int $windowMinutes,
    ): bool {
        $users = $this->hits->users($detector, $counted);

        $reason = sprintf(
            'Auto-blocked: %s reached %d in %d min',
            $detector,
            $threshold,
            $windowMinutes,
        );

        // The ids, not just the count: an operator deciding whether to arm a
        // detector needs to see WHO was behind a flagged address, since
        // "three users" reads very differently from three ids they recognise
        // as staff. Empty for anonymous traffic, which is most of it.
        $context = [
            'detector'       => $detector,
            'threshold'      => $threshold,
            'window_minutes' => $windowMinutes,
            'hits'           => $hits,
            'user_ids'       => $users,
        ];

        $notBlockedBecause = $this->holdBack($mode, count($users), $this->sharedIpUserThreshold());

        if ($notBlockedBecause !== null) {
            $this->logWouldHaveBlocked($ip, $reason, $notBlockedBecause, count($users), $context);

            return false;
        }

        try {
            $this->blacklist->block($ip, [
                'reason'     => $reason,
                'source'     => BlockSource::Auto,
                'expires_at' => now()->addMinutes((int) config('watchtower.auto_block.block_duration_minutes', 60)),
            ]);
        } catch (NeverAutoBlockException) {
            $this->logWouldHaveBlocked($ip, $reason, 'never_auto_block', count($users), $context);

            return false;
        } catch (NeverBlockException) {
            Log::channel(config('watchtower.log_channel', 'stack'))
                ->debug('Watchtower: auto-block skipped for whitelisted IP', ['ip' => $ip]);

            return false;
        }

        // The counter has done its job, and leaving it at the threshold
        // would re-trigger on the first signal after the block lapses.
        $this->hits->forget($detector, $counted);

        return true;
    }

    /**
     * Which guard, if any, holds a block back once a rule or detector has
     * matched — shared so both ends of the engine answer this identically.
     *
     * never_auto_block isn't here: it lives in BlacklistService::block(), so
     * that a new automated path can't forget it.
     *
     * The threshold is passed in rather than read here because parsing it
     * warns on a bad value, and run() resolves it once for a whole tick —
     * reading it per offender would repeat that warning per offender.
     */
    private function holdBack(string $mode, int $distinctUsers, int $sharedIpThreshold): ?string
    {
        return match (true) {
            $mode === 'warn' => 'warn mode',
            $sharedIpThreshold > 0 && $distinctUsers >= $sharedIpThreshold => 'shared IP',
            default => null,
        };
    }

    public function run(): void
    {
        if (! config('watchtower.auto_block.enabled', false)) {
            return;
        }

        $rules = config('watchtower.auto_block.rules', []);
        $durationMinutes = (int) config('watchtower.auto_block.block_duration_minutes', 60);
        $globalMode = $this->normaliseMode(config('watchtower.auto_block.mode', 'warn'));
        $sharedIpThreshold = $this->sharedIpUserThreshold();

        foreach ($rules as $index => $rule) {
            $mode = $this->resolveRuleMode($rule, $globalMode);

            if ($mode === 'disabled') {
                continue;
            }

            $this->applyRule($rule, (int) $index, $mode, $durationMinutes, $sharedIpThreshold);
        }
    }

    /**
     * Per-rule `mode` overrides the global mode. Both fall back to 'warn'
     * when missing or invalid, so a rule is a dry run until someone arms it
     * on purpose. A rule is written from a guess about traffic nobody has
     * looked at yet, and the cost of guessing wrong is locking out real
     * users — so the untouched setting is the one that only reports.
     *
     * A rule that names a mode is answered on its own terms: misspell it and
     * you get 'warn', not the global mode. Inheriting instead would mean
     * that `'mode' => 'warm'` under an armed global silently blocks — the
     * one outcome the typo was least likely to have intended.
     */
    private function resolveRuleMode(array $rule, string $globalMode): string
    {
        if (isset($rule['mode'])) {
            return $this->normaliseMode($rule['mode']);
        }

        return $globalMode;
    }

    /**
     * Distinct signed-in users from one address before a block downgrades.
     *
     * `0` switches the guard off, which is what makes a bare `(int)` cast
     * the wrong tool: a blank or misspelled env value casts to 0 too, and
     * would quietly remove the protection this feature exists to provide.
     * Anything that isn't a whole number falls back to the default and says
     * so, since the safe reading of a typo is "they meant to have a guard".
     */
    private function sharedIpUserThreshold(): int
    {
        $configured = config(
            'watchtower.auto_block.shared_ip_user_threshold',
            self::DEFAULT_SHARED_IP_USER_THRESHOLD,
        );

        if (is_int($configured) && $configured >= 0) {
            return $configured;
        }

        if (is_string($configured) && ctype_digit(trim($configured))) {
            return (int) trim($configured);
        }

        Log::channel(config('watchtower.log_channel', 'stack'))->warning(
            'Watchtower: shared_ip_user_threshold is not a whole number, so the shared-IP guard fell back to its default.',
            [
                'configured' => $configured,
                'using'      => self::DEFAULT_SHARED_IP_USER_THRESHOLD,
                'hint'       => 'Set WATCHTOWER_SHARED_IP_USER_THRESHOLD to a whole number, or to 0 to switch the guard off on purpose.',
            ],
        );

        return self::DEFAULT_SHARED_IP_USER_THRESHOLD;
    }

    private function normaliseMode(mixed $mode): string
    {
        return is_string($mode) && in_array($mode, self::VALID_MODES, true)
            ? $mode
            : 'warn';
    }

    private function applyRule(array $rule, int $ruleIndex, string $mode, int $durationMinutes, int $sharedIpThreshold): void
    {
        $windowMinutes   = (int) ($rule['window_minutes'] ?? 5);
        $threshold       = (int) ($rule['count'] ?? 10);
        $level           = $rule['level'] ?? null;
        $messageContains = $rule['message_contains'] ?? null;

        $logsTable = config('logscope.table', 'log_entries');
        $windowStart = now()->subMinutes($windowMinutes);

        $query = DB::table($logsTable)
            ->select('ip_address', DB::raw('count(*) as hit_count'))
            ->whereNotNull('ip_address')
            ->where('occurred_at', '>=', $windowStart)
            ->groupBy('ip_address')
            ->having('hit_count', '>=', $threshold);

        if ($level) {
            $query->where('level', $level);
        }

        if ($messageContains) {
            $query->where('message', 'like', '%'.$messageContains.'%');
        }

        // Dropped before the user-count query so it isn't computed for
        // addresses that are already blocked — their rows keep matching for
        // the rest of the window, so they reappear on every tick. Still
        // re-checked in the loop below, because blocking one IPv6 address
        // covers its whole prefix and can block a later offender mid-loop.
        $offenders = $query->pluck('ip_address')
            ->reject(fn (string $ip): bool => $this->blacklist->isBlocked($ip))
            ->values();

        if ($offenders->isEmpty()) {
            return;
        }

        $distinctUsers = $this->distinctUsersPerIp($logsTable, $offenders->all(), $windowStart);

        $expiresAt = now()->addMinutes($durationMinutes);
        $reason = sprintf(
            'Auto-blocked: %s%s exceeded %d hits in %d min',
            $level ? "level={$level} " : '',
            $messageContains ? "contains='{$messageContains}' " : '',
            $threshold,
            $windowMinutes,
        );

        foreach ($offenders as $ip) {
            if ($this->blacklist->isBlocked($ip)) {
                continue;
            }

            $users = $distinctUsers[$ip] ?? 0;

            $context = [
                'rule_index'     => $ruleIndex,
                'rule'           => $rule,
                'threshold'      => $threshold,
                'window_minutes' => $windowMinutes,
            ];

            $notBlockedBecause = $this->holdBack($mode, $users, $sharedIpThreshold);

            if ($notBlockedBecause !== null) {
                $this->logWouldHaveBlocked($ip, $reason, $notBlockedBecause, $users, $context);

                continue;
            }

            // mode === 'block'
            try {
                $this->blacklist->block($ip, [
                    'reason'     => $reason,
                    'source'     => BlockSource::Auto,
                    'expires_at' => $expiresAt,
                ]);
            } catch (NeverAutoBlockException) {
                // Caught before NeverBlockException, its parent: this one is
                // a rule that fired on real traffic and was held back, which
                // is worth the same visibility as any other near miss.
                $this->logWouldHaveBlocked($ip, $reason, 'never_auto_block', $users, $context);
            } catch (NeverBlockException) {
                Log::channel(config('watchtower.log_channel', 'stack'))
                    ->debug('Watchtower: auto-block skipped for whitelisted IP', ['ip' => $ip]);
            }
        }
    }

    /**
     * How many distinct signed-in users the log saw from each of these
     * addresses across the window.
     *
     * Deliberately not filtered by the rule. The question is how many people
     * a block would hit, not how many of them tripped it: an address where
     * one buggy client throws every error while two hundred others browse
     * fine is exactly the case worth catching. Anonymous rows count for
     * nobody, since COUNT(DISTINCT) skips NULL.
     *
     * @param  list<string>  $ips
     * @return array<string, int>
     */
    private function distinctUsersPerIp(string $logsTable, array $ips, \DateTimeInterface $windowStart): array
    {
        return DB::table($logsTable)
            ->select('ip_address', DB::raw('count(distinct user_id) as user_count'))
            ->whereIn('ip_address', $ips)
            ->whereNotNull('user_id')
            ->where('occurred_at', '>=', $windowStart)
            ->groupBy('ip_address')
            ->pluck('user_count', 'ip_address')
            ->map(static fn ($count): int => (int) $count)
            ->all();
    }

    /**
     * Emit a structured "would have blocked" log entry. The
     * `would_have_blocked: true` key is the canonical filter — operators
     * can grep for it (or query LogScope) to see exactly which IPs a rule
     * would have caught before they flip the mode to 'block'.
     *
     * `not_blocked_because` says which of the three held it back, so a rule
     * that is merely unarmed reads differently from one that fired and was
     * overruled by the shared-IP guard or never_auto_block.
     *
     * `$identity` is whatever names the thing that matched — the rule and
     * its index for a scheduled rule, the detector and its hit count for a
     * real-time one — so one log shape covers both ends of the engine.
     *
     * @param  array<string, mixed>  $identity
     */
    private function logWouldHaveBlocked(
        string $ip,
        string $reason,
        string $notBlockedBecause,
        int $distinctUsers,
        array $identity = [],
    ): void {
        $context = [
            'would_have_blocked'  => true,
            'ip'                  => $ip,
            ...$identity,
            'reason'              => $reason,
            'not_blocked_because' => $notBlockedBecause,
            'distinct_users'      => $distinctUsers,
        ];

        if ($notBlockedBecause === 'warn mode') {
            // Otherwise a correctly-configured dry run looks like a package
            // that quietly does nothing.
            $context['hint'] = 'Auto-block is in warn mode, so nothing was blocked. '
                ."Set WATCHTOWER_AUTO_BLOCK_MODE=block, or the rule's or detector's own 'mode', once these look right.";
        }

        Log::channel(config('watchtower.log_channel', 'stack'))->warning(
            'Watchtower: would-have-blocked (auto-block did not block)',
            $context,
        );
    }
}
