<?php

declare(strict_types=1);

namespace Watchtower\Services;

use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;
use Watchtower\Enums\BlockSource;
use Watchtower\Exceptions\NeverAutoBlockException;
use Watchtower\Exceptions\NeverBlockException;
use Watchtower\Exceptions\UnknownScopeException;
use Watchtower\Support\BlockScope;
use Watchtower\Support\FailureWindow;
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
        // Fail open, the way BlockedIpMiddleware does. This runs inside the
        // request — in middleware, and in an event listener inside the auth
        // flow — so a cache backend that is down or slow must not turn an
        // ordinary 404 or a failed login into a 500. Detection is a
        // best-effort layer on top of the app; it is never worth the app
        // itself. Losing a few counts during an outage is the right trade.
        try {
            return $this->detect($detector, $ip, $userId);
        } catch (\Throwable $e) {
            $this->reportDetectorFailure($e);

            return false;
        }
    }

    /**
     * Count one signal and decide. See record(), which is this behind a
     * fail-open guard.
     */
    private function detect(string $detector, string $ip, int|string|null $userId): bool
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

        $scope = $this->resolveScope($settings, $detector);

        if ($scope === null) {
            return false;
        }

        // Already blocked: don't count, and don't block again. A blocked
        // scanner keeps knocking, and re-blocking on every knock would
        // restart the duration each time and never let it lapse.
        //
        // A scoped detector asks about its own scope as well, since a block
        // it made earlier lives there rather than in the global list.
        if ($this->blacklist->isBlocked($ip)
            || ($scope !== BlockScope::GLOBAL && $this->blacklist->isBlocked($ip, $scope))) {
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

        return $this->blockDetected(
            $detector,
            $ip,
            $counted,
            $mode,
            $scope,
            $hits,
            $threshold,
            $windowMinutes,
            // Resolved once here rather than inside the decision, for the
            // reason holdBack() gives: parsing it warns on a bad value, and
            // this runs per request rather than per tick.
            $this->sharedIpUserThreshold(),
        );
    }

    /**
     * Log the detector failure at most once per window — every request hits
     * this during a cache outage, and a line per request fills the disk
     * while the backend is already struggling.
     */
    private function reportDetectorFailure(\Throwable $e): void
    {
        if (FailureWindow::isOpen('detector')) {
            return;
        }

        FailureWindow::open('detector');

        try {
            Log::channel(config('watchtower.log_channel', 'stack'))
                ->error('Watchtower: detector failed, letting the request through uncounted', [
                    'error' => $e->getMessage(),
                ]);
        } catch (\Throwable) {
            // A broken log channel must not undo the fail-open.
        }
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
        string $scope,
        int $hits,
        int $threshold,
        int $windowMinutes,
        int $sharedIpThreshold,
    ): bool {
        // Read before clearing below — forget() drops the user set too.
        $users = $this->hits->users($detector, $counted);

        // Whatever is decided below, this crossing has been answered, so the
        // count starts again. Clearing here rather than only on a successful
        // block is what stops a held-back detector re-reporting per request:
        // warn mode never blocks, so a counter left sitting at its threshold
        // would re-decide — and re-log — on every matching request for the
        // rest of the window. A scanner sending thousands would write
        // thousands of near-identical lines, which is both a disk-filling
        // handle for an unauthenticated attacker and the fastest way to
        // drown the dry run warn mode exists for. It now reports once per
        // `count` signals instead, the same cadence a rule reports at once
        // per tick. Blocking clears it for its own reason too: a lapsed
        // block shouldn't re-fire on the very next signal.
        $this->hits->forget($detector, $counted);

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

        return $this->blockOrReport(
            $ip,
            $reason,
            $mode,
            $scope,
            count($users),
            $sharedIpThreshold,
            now()->addMinutes((int) config('watchtower.auto_block.block_duration_minutes', 60)),
            $context,
        );
    }

    /**
     * Apply the guards, then block or report the near miss.
     *
     * Shared by both ends of the engine — the real-time detectors and the
     * scheduled log rules — so the shared-IP downgrade, the never_* refusals
     * and the would-have-blocked log cannot drift apart. Writing this twice
     * is the duplication issue #38 is open about, one table over.
     *
     * @param  array<string, mixed>  $context
     * @return bool whether the address ended up blocked
     */
    private function blockOrReport(
        string $ip,
        string $reason,
        string $mode,
        string $scope,
        int $distinctUsers,
        int $sharedIpThreshold,
        \DateTimeInterface $expiresAt,
        array $context,
    ): bool {
        $notBlockedBecause = $this->holdBack($mode, $distinctUsers, $sharedIpThreshold);

        // A shared address on a scoped rule is the case scopes exist for.
        // Warning and moving on protects the people behind that gateway and
        // leaves the attacker among them free; a scoped block takes away the
        // routes the evidence points at and leaves everyone else the rest of
        // the app.
        //
        // ONLY this hold-back converts. `warn` mode is a dry run and has to
        // stay one, or arming nothing would start blocking. never_auto_block
        // is a refusal about an address, not a decision about reach, and it
        // is enforced in BlacklistService::block() regardless.
        $downgraded = $notBlockedBecause === 'shared IP' && $scope !== BlockScope::GLOBAL;

        if ($downgraded) {
            $notBlockedBecause = null;
        }

        if ($notBlockedBecause !== null) {
            $this->logWouldHaveBlocked($ip, $reason, $notBlockedBecause, $distinctUsers, $context);

            return false;
        }

        try {
            $this->blacklist->block($ip, [
                'reason'     => $reason,
                'source'     => BlockSource::Auto,
                'expires_at' => $expiresAt,
                'scope'      => $scope,
            ]);
        } catch (NeverAutoBlockException) {
            // Caught before NeverBlockException, its parent: this one is a
            // rule that fired on real traffic and was held back, which is
            // worth the same visibility as any other near miss.
            $this->logWouldHaveBlocked($ip, $reason, 'never_auto_block', $distinctUsers, $context);

            return false;
        } catch (NeverBlockException) {
            Log::channel(config('watchtower.log_channel', 'stack'))
                ->debug('Watchtower: auto-block skipped for whitelisted IP', ['ip' => $ip]);

            return false;
        }

        if ($downgraded) {
            // Deliberately NOT a would-have-blocked line. `would_have_blocked`
            // stays the canonical filter for things that did not happen, and
            // this one did — an operator filtering on it must not find a real
            // block hiding among the near misses.
            Log::channel(config('watchtower.log_channel', 'stack'))
                ->warning('Watchtower: shared address blocked in scope instead of app-wide', [
                    'ip'                  => $ip,
                    ...$context,
                    'reason'              => $reason,
                    'downgraded_to_scope' => $scope,
                    'distinct_users'      => $distinctUsers,
                ]);
        }

        return true;
    }

    /**
     * The scope a rule or detector blocks in, or null when it names one the
     * config doesn't declare.
     *
     * An undeclared name blocks nothing, loudly. That matches how an invalid
     * `mode` falls back to the side that doesn't act against users: treating
     * a typo as the global scope would block far more than was asked for,
     * and storing it as written would enforce nothing while reporting itself
     * as a block.
     *
     * Throttled, because a detector reads this per signal rather than per
     * tick, and a misconfigured one would otherwise write a line per request.
     *
     * @param  array<string, mixed>  $settings
     */
    private function resolveScope(array $settings, string $label): ?string
    {
        try {
            return BlockScope::normalize($settings['scope'] ?? null);
        } catch (UnknownScopeException $e) {
            // One window for every rule and detector, not one each. The name
            // becomes a file name, so it can't carry a label; and a second
            // misconfigured scope staying quiet for a minute costs nothing,
            // because the message below names the one it did report and both
            // are the same fix.
            if (! FailureWindow::isOpen('scope')) {
                FailureWindow::open('scope');

                Log::channel(config('watchtower.log_channel', 'stack'))
                    ->warning('Watchtower: auto-block skipped, its scope is not declared', [
                        'rule'  => $label,
                        'scope' => $settings['scope'] ?? null,
                        'error' => $e->getMessage(),
                    ]);
            }

            return null;
        }
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

            $scope = $this->resolveScope((array) $rule, "rule #{$index}");

            if ($scope === null) {
                continue;
            }

            $this->applyRule($rule, (int) $index, $mode, $scope, $durationMinutes, $sharedIpThreshold);
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

    private function applyRule(array $rule, int $ruleIndex, string $mode, string $scope, int $durationMinutes, int $sharedIpThreshold): void
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

            $this->blockOrReport($ip, $reason, $mode, $scope, $users, $sharedIpThreshold, $expiresAt, $context);
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
