<?php

declare(strict_types=1);

namespace Watchtower\Services;

use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;
use Watchtower\Enums\BlockSource;
use Watchtower\Exceptions\NeverBlockException;

class AutoBlockService
{
    /**
     * Valid auto-block modes. Anything else falls back to 'block'.
     */
    private const VALID_MODES = ['block', 'warn', 'disabled'];

    public function __construct(private readonly BlacklistService $blacklist) {}

    public function run(): void
    {
        if (! config('watchtower.auto_block.enabled', false)) {
            return;
        }

        $rules = config('watchtower.auto_block.rules', []);
        $durationMinutes = (int) config('watchtower.auto_block.block_duration_minutes', 60);
        $globalMode = $this->normaliseMode(config('watchtower.auto_block.mode', 'block'));

        foreach ($rules as $index => $rule) {
            $mode = $this->resolveRuleMode($rule, $globalMode);

            if ($mode === 'disabled') {
                continue;
            }

            $this->applyRule($rule, (int) $index, $mode, $durationMinutes);
        }
    }

    /**
     * Per-rule `mode` overrides the global mode. Both fall back to 'block'
     * when missing or invalid — preserves the pre-warn-mode behaviour for
     * configs that don't specify a mode at all.
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
            : 'block';
    }

    private function applyRule(array $rule, int $ruleIndex, string $mode, int $durationMinutes): void
    {
        $windowMinutes   = (int) ($rule['window_minutes'] ?? 5);
        $threshold       = (int) ($rule['count'] ?? 10);
        $level           = $rule['level'] ?? null;
        $messageContains = $rule['message_contains'] ?? null;

        $logsTable = config('logscope.table', 'log_entries');

        $query = DB::table($logsTable)
            ->select('ip_address', DB::raw('count(*) as hit_count'))
            ->whereNotNull('ip_address')
            ->where('occurred_at', '>=', now()->subMinutes($windowMinutes))
            ->groupBy('ip_address')
            ->having('hit_count', '>=', $threshold);

        if ($level) {
            $query->where('level', $level);
        }

        if ($messageContains) {
            $query->where('message', 'like', '%'.$messageContains.'%');
        }

        $offenders = $query->pluck('ip_address');

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

            if ($mode === 'warn') {
                $this->logWouldHaveBlocked($ip, $ruleIndex, $rule, $threshold, $windowMinutes, $reason);

                continue;
            }

            // mode === 'block'
            try {
                $this->blacklist->block($ip, [
                    'reason'     => $reason,
                    'source'     => BlockSource::Auto,
                    'expires_at' => $expiresAt,
                ]);
            } catch (NeverBlockException) {
                Log::channel(config('watchtower.log_channel', 'stack'))
                    ->debug('Watchtower: auto-block skipped for whitelisted IP', ['ip' => $ip]);
            }
        }
    }

    /**
     * Emit a structured "would have blocked" log entry. The
     * `would_have_blocked: true` key is the canonical filter — operators
     * can grep for it (or query LogScope) to see exactly which IPs a rule
     * would have caught before they flip the mode to 'block'.
     */
    private function logWouldHaveBlocked(
        string $ip,
        int $ruleIndex,
        array $rule,
        int $threshold,
        int $windowMinutes,
        string $reason,
    ): void {
        Log::channel(config('watchtower.log_channel', 'stack'))->warning(
            'Watchtower: would-have-blocked (auto-block in warn mode)',
            [
                'would_have_blocked' => true,
                'ip'                 => $ip,
                'rule_index'         => $ruleIndex,
                'rule'               => $rule,
                'threshold'          => $threshold,
                'window_minutes'     => $windowMinutes,
                'reason'             => $reason,
            ],
        );
    }
}
