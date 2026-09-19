<?php

declare(strict_types=1);

namespace Watchtower\Services;

use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;
use Watchtower\Enums\BlockSource;
use Watchtower\Exceptions\NeverAutoBlockException;
use Watchtower\Exceptions\NeverBlockException;

class AutoBlockService
{
    /**
     * Valid auto-block modes. Anything else falls back to 'warn', the safe
     * end of the range: a typo in the mode shouldn't start blocking people.
     */
    private const VALID_MODES = ['block', 'warn', 'disabled'];

    /** Distinct signed-in users from one address before a block downgrades. */
    private const DEFAULT_SHARED_IP_USER_THRESHOLD = 3;

    public function __construct(private readonly BlacklistService $blacklist) {}

    public function run(): void
    {
        if (! config('watchtower.auto_block.enabled', false)) {
            return;
        }

        $rules = config('watchtower.auto_block.rules', []);
        $durationMinutes = (int) config('watchtower.auto_block.block_duration_minutes', 60);
        $globalMode = $this->normaliseMode(config('watchtower.auto_block.mode', 'warn'));

        foreach ($rules as $index => $rule) {
            $mode = $this->resolveRuleMode($rule, $globalMode);

            if ($mode === 'disabled') {
                continue;
            }

            $this->applyRule($rule, (int) $index, $mode, $durationMinutes);
        }
    }

    /**
     * Per-rule `mode` overrides the global mode. Both fall back to 'warn'
     * when missing or invalid, so a rule is a dry run until someone arms it
     * on purpose. A rule is written from a guess about traffic nobody has
     * looked at yet, and the cost of guessing wrong is locking out real
     * users — so the untouched setting is the one that only reports.
     */
    private function resolveRuleMode(array $rule, string $globalMode): string
    {
        if (isset($rule['mode']) && in_array($rule['mode'], self::VALID_MODES, true)) {
            return $rule['mode'];
        }

        return $globalMode;
    }

    private function normaliseMode(mixed $mode): string
    {
        return is_string($mode) && in_array($mode, self::VALID_MODES, true)
            ? $mode
            : 'warn';
    }

    private function applyRule(array $rule, int $ruleIndex, string $mode, int $durationMinutes): void
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

        $offenders = $query->pluck('ip_address');

        if ($offenders->isEmpty()) {
            return;
        }

        $distinctUsers = $this->distinctUsersPerIp($logsTable, $offenders->all(), $windowStart);
        $sharedIpThreshold = (int) config(
            'watchtower.auto_block.shared_ip_user_threshold',
            self::DEFAULT_SHARED_IP_USER_THRESHOLD,
        );

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

            $notBlockedBecause = match (true) {
                $mode === 'warn' => 'warn mode',
                $sharedIpThreshold > 0 && $users >= $sharedIpThreshold => 'shared IP',
                default => null,
            };

            if ($notBlockedBecause !== null) {
                $this->logWouldHaveBlocked($ip, $ruleIndex, $rule, $threshold, $windowMinutes, $reason, $notBlockedBecause, $users);

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
                $this->logWouldHaveBlocked($ip, $ruleIndex, $rule, $threshold, $windowMinutes, $reason, 'never_auto_block', $users);
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
     */
    private function logWouldHaveBlocked(
        string $ip,
        int $ruleIndex,
        array $rule,
        int $threshold,
        int $windowMinutes,
        string $reason,
        string $notBlockedBecause,
        int $distinctUsers,
    ): void {
        $context = [
            'would_have_blocked'  => true,
            'ip'                  => $ip,
            'rule_index'          => $ruleIndex,
            'rule'                => $rule,
            'threshold'           => $threshold,
            'window_minutes'      => $windowMinutes,
            'reason'              => $reason,
            'not_blocked_because' => $notBlockedBecause,
            'distinct_users'      => $distinctUsers,
        ];

        if ($notBlockedBecause === 'warn mode') {
            // Otherwise a correctly-configured dry run looks like a package
            // that quietly does nothing.
            $context['hint'] = 'Auto-block is in warn mode, so nothing was blocked. '
                ."Set WATCHTOWER_AUTO_BLOCK_MODE=block, or the rule's own 'mode', once these look right.";
        }

        Log::channel(config('watchtower.log_channel', 'stack'))->warning(
            'Watchtower: would-have-blocked (auto-block did not block)',
            $context,
        );
    }
}
