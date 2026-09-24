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
use Watchtower\Support\NeverBlockList;

class AutoBlockService
{
    /**
     * Valid auto-block modes. Anything else falls back to 'warn', the safe
     * end of the range: a typo in the mode shouldn't start blocking people.
     */
    public const VALID_MODES = ['block', 'warn', 'disabled'];

    /**
     * Distinct signed-in users from one address before a block downgrades.
     *
     * Public, like VALID_MODES above, because `watchtower:simulate` reports
     * what THIS engine would have done and has to answer from the same
     * numbers. A second copy in the command is how the report starts
     * describing an engine that no longer exists.
     */
    public const DEFAULT_SHARED_IP_USER_THRESHOLD = 3;

    /**
     * The hold-back holdBack() reports for a shared address, and the reason
     * the `not_blocked_because` log key carries for one.
     *
     * A constant because three places now turn on this exact answer and not
     * on the others: the scoped downgrade, and the detector hold that
     * deliberately excludes it. It is the one hold-back that is a live
     * measurement rather than a standing setting, so the two that treat it
     * specially have to agree on which one it is.
     */
    private const HELD_BY_SHARED_IP = 'shared IP';

    public function __construct(
        private readonly BlacklistService $blacklist,
        private readonly HitWindow $hits,
        private readonly OffenceLedger $offences,
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
     * @param  bool|null  $blocked  whether this address is already blocked
     *                              app-wide, when the caller already knows.
     *                              BlockedIpMiddleware resolves it for every
     *                              request and stashes it — see
     *                              BlockedIpMiddleware::BLOCKED — so passing
     *                              it saves repeating two cache reads on a
     *                              path an attacker sets the pace of. Null
     *                              means look it up.
     * @return bool whether the address is blocked APP-WIDE now — the
     *              scanner-path detector answers the request itself when it
     *              is. A detector with a scope never returns true, because
     *              this runs in the global middleware stack and a scoped
     *              block must only be enforced by the route middleware
     *              carrying its scope.
     */
    public function record(string $detector, string $ip, int|string|null $userId = null, ?bool $blocked = null): bool
    {
        // Fail open, the way BlockedIpMiddleware does. This runs inside the
        // request — in middleware, and in an event listener inside the auth
        // flow — so a cache backend that is down or slow must not turn an
        // ordinary 404 or a failed login into a 500. Detection is a
        // best-effort layer on top of the app; it is never worth the app
        // itself. Losing a few counts during an outage is the right trade.
        try {
            return $this->detect($detector, $ip, $userId, $blocked);
        } catch (\Throwable $e) {
            $this->reportDetectorFailure($e);

            return false;
        }
    }

    /**
     * Count one signal and decide. See record(), which is this behind a
     * fail-open guard.
     */
    private function detect(string $detector, string $ip, int|string|null $userId, ?bool $blocked = null): bool
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
        // $blocked is the answer BlockedIpMiddleware already paid for on this
        // request; asking again repeats both of its cache reads for a value
        // that can only have changed in the microseconds since.
        if ($blocked ?? $this->blacklist->isBlocked($ip)) {
            return true;
        }

        // Already blocked where this detector aims, so there is still nothing
        // to count — but the answer is false, not true. record()'s callers
        // run in the GLOBAL middleware stack and answer the request when this
        // returns true, which for a scoped block would enforce it on every
        // route in the app. The route middleware carrying the scope is what
        // enforces a scoped block; nothing here may do it on its behalf.
        if ($this->blockedInScope($ip, $scope)) {
            return false;
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

        $blocked = $this->blockDetected(
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

        // Only an app-wide block licenses the caller to answer the request.
        // A scoped block was still made — it is simply not this stack's to
        // enforce. See the scoped early return above.
        return $blocked && $scope === BlockScope::GLOBAL;
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
        // This detector has already decided about this address and was held
        // back from enforcing it. Honour that decision for as long as the
        // block would have lasted, the way the isBlocked() check in detect()
        // honours a real one: a blocked scanner never reaches the counter at
        // all, so a dry run that keeps re-deciding is not predicting what
        // arming would do — it is describing traffic a real block would have
        // stopped.
        //
        // Checked here, past the threshold, rather than before the counter:
        // a `response_bursts` signal that is 12 of 40 must stay two cache
        // operations, and putting this in front of hit() would have added a
        // third to every one of them — undoing on the loosest, highest-volume
        // detector what was just won on all of them. Here it is paid only by
        // a signal that already crossed, and it replaces strictly more than
        // it costs: the close(), the user read and the log write below.
        //
        // Leaving the counter running is deliberate too. It decays on its own
        // window, and not clearing it means nothing is written for a held
        // address beyond the hit it was already paying for.
        //
        // The reason the hold was opened under matters as much as the mode.
        // The hold is keyed on $counted — the prefix a block would cover —
        // but a never_* refusal names ONE address: BlacklistService::block()
        // checks it before the target is widened. Served raw, such a hold
        // would exempt every address in the prefix, most of which are on no
        // list at all. holdStillSpeaksFor() re-asks the list for the address
        // now asking.
        if ($this->isHeld($detector, $counted, $ip, $mode)) {
            return false;
        }

        // Whatever is decided below, this crossing has been answered, so the
        // count starts again. Blocking clears it so a lapsed block doesn't
        // re-fire on the very next signal; a held-back decision clears it so
        // a counter left sitting at its threshold doesn't re-decide on every
        // matching request for the rest of the window.
        //
        // That second reason only ever amortised by `count`, though, and
        // `scanner_paths` ships `count => 1` deliberately — a single request
        // for /.env is not a mistake, and accumulating before blocking would
        // both serve the matched request and hand an attacker room to game
        // the shared-IP guard. A divisor of 1 is no divisor: every probe
        // crossed, closed and logged. What actually bounds the repeat rate
        // is the notional block opened below, which keeps the address away
        // from the detector the way a real block would have.
        //
        // close() hands back the users seen in the window it is closing, so
        // they are read before they are dropped rather than in a separate
        // call that has to be kept above this one.
        $users = $this->hits->close($detector, $counted);

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

        $durationMinutes = (int) config('watchtower.auto_block.block_duration_minutes', 60);

        $heldBy = $this->blockOrReport(
            $ip,
            $reason,
            $mode,
            $scope,
            count($users),
            $sharedIpThreshold,
            $durationMinutes,
            $context,
        );

        $this->holdDecision($detector, $counted, $mode, $heldBy, $durationMinutes);

        return $heldBy === null;
    }

    /**
     * Whether $holder already decided about this address and was held back,
     * in this mode, by a hold-back that still speaks for $ip. See
     * holdDecision(), which opens what this reads.
     */
    private function isHeld(string $holder, string $counted, string $ip, string $mode): bool
    {
        $hold = $this->hits->notionalHold($holder, $counted);

        return $hold !== null && $hold['mode'] === $mode && $this->holdStillSpeaksFor($hold['reason'], $ip);
    }

    /**
     * A decision blockOrReport() reported rather than enforced: hold it for as
     * long as the block would have run.
     *
     * Shared by both ends of the engine for the reason blockOrReport() is: a
     * detector and a rule held back by the same thing must stay held on the
     * same terms, or `watchtower:simulate` — which models the hold — agrees
     * with one half and not the other.
     *
     * A real block takes the address out of play — the detector returns at
     * its blocklist check, a rule drops it from its offenders — and nothing
     * did that for a decision that was only reported. Holding it means a dry
     * run reads as one entry per block it predicts rather than one per
     * request or per scheduler tick, and an address automation is refused
     * permission to touch stops costing a decision each time.
     *
     * NOT for the shared-IP guard, which is the one hold-back that is a
     * live measurement rather than a standing setting. `warn` mode and
     * never_auto_block are config: they will say the same thing in an
     * hour, so honouring them for an hour changes nothing. How many
     * signed-in users an address is showing changes minute to minute, and
     * holding that answer would convert a guard an attacker has to keep
     * re-earning — three accounts live in a one-minute window, for
     * response_bursts — into an hour of immunity bought once. The README
     * is explicit that this guard is not a control an adversary respects;
     * that is a reason to leave it re-measured, not to make it stickier.
     * It also needs no hold: it cannot fire at `count => 1`, where at
     * most the current request's own user is known, so `scanner_paths` never
     * reaches it.
     *
     * The flat duration, never the escalated one: escalatedMinutes() is
     * only consulted past every hold-back, because a near miss is not an
     * offence and must not lengthen anything.
     *
     * The reason is stored with the hold because a never_* refusal is
     * about one address and the key is about a prefix — see
     * holdStillSpeaksFor(), which is what reads it back.
     */
    private function holdDecision(string $holder, string $counted, string $mode, ?string $heldBy, int $durationMinutes): void
    {
        if ($heldBy !== null && $heldBy !== self::HELD_BY_SHARED_IP) {
            $this->hits->openNotionalBlock($holder, $counted, $mode, $heldBy, max(1, $durationMinutes) * 60);
        }
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
     * @return string|null why the address did NOT end up blocked, or null if
     *                     it did. Both callers hold a reported decision for
     *                     the span the block would have run, and which
     *                     hold-back produced it decides whether they may —
     *                     see holdDecision(). A caller that only needs the
     *                     outcome compares against null.
     */
    private function blockOrReport(
        string $ip,
        string $reason,
        string $mode,
        string $scope,
        int $distinctUsers,
        int $sharedIpThreshold,
        int $durationMinutes,
        array $context,
    ): ?string {
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
        $downgraded = $notBlockedBecause === self::HELD_BY_SHARED_IP && $scope !== BlockScope::GLOBAL;

        if ($downgraded) {
            $notBlockedBecause = null;
        }

        if ($notBlockedBecause !== null) {
            $this->logWouldHaveBlocked($ip, $reason, $notBlockedBecause, $distinctUsers, $context);

            return $notBlockedBecause;
        }

        // Only past every hold-back, and never before: a warn-mode dry run
        // and an address held back for being shared are not offences, and
        // moving either up the ladder would lengthen a future block on the
        // strength of ones that never happened. The shared-IP downgrade
        // converted above is a real block, so it counts like any other.
        $expiresAt = now()->addMinutes(
            $this->escalatedMinutes($ip, $scope, $durationMinutes),
        );

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

            return 'never_auto_block';
        } catch (NeverBlockException) {
            Log::channel(config('watchtower.log_channel', 'stack'))
                ->debug('Watchtower: auto-block skipped for whitelisted IP', ['ip' => $ip]);

            return 'never_block';
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

        // Nothing held it back — including the downgraded case, which is a
        // real block narrowed to a scope rather than a near miss.
        return null;
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
     * Whether a scoped rule or detector has already blocked this address in
     * its own scope.
     *
     * Shared by both ends of the engine, because both must skip an address
     * they have already dealt with and they answer it differently otherwise.
     * A scoped block leaves the address globally free, so `isBlocked($ip)`
     * alone is always false for one — which let the scheduled path re-block
     * the same offender on every tick, sliding `expires_at` forward so the
     * block never lapsed and re-firing IpBlocked (and the webhook) each time.
     *
     * Always false for the global scope: that case is `isBlocked($ip)`, which
     * every caller checks first.
     */
    private function blockedInScope(string $ip, string $scope): bool
    {
        return $scope !== BlockScope::GLOBAL && $this->blacklist->isBlocked($ip, $scope);
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
            $sharedIpThreshold > 0 && $distinctUsers >= $sharedIpThreshold => self::HELD_BY_SHARED_IP,
            default => null,
        };
    }

    /**
     * Whether a hold opened on this prefix still answers for the address now
     * asking.
     *
     * 'warn mode' is a stance about the detector, not the address: it covers
     * the prefix evenly, and arming is already answered by the mode the hold
     * was opened under, so nothing is re-asked. Any future hold-back that is
     * likewise config-level lands in this branch by default, which is the
     * safe direction — the whole engine falls back to NOT blocking on
     * ambiguity.
     *
     * A never_* refusal is different. It names ONE address, checked in
     * BlacklistService::block() before the target is widened, while the hold
     * it opened covers the whole prefix a block would have. Honouring it for
     * every address in that prefix would let one exempt entry shield its
     * /64 — none of them counted, evaluated, logged or blocked. So the list
     * is re-asked for the address now asking: memoised in NeverBlockList, no
     * round trip. That is also what makes taking an address off the list
     * take effect on its next signal rather than when the hold lapses.
     */
    private function holdStillSpeaksFor(string $reason, string $ip): bool
    {
        if ($reason !== 'never_auto_block' && $reason !== 'never_block') {
            return true;
        }

        return NeverBlockList::refusesAutoBlock($ip);
    }

    /**
     * How long this block should last, once the offence ledger has had its
     * say — the flat duration for a first offence, a longer rung for an
     * address that keeps coming back.
     *
     * Normalized first, because a block widens a single IPv6 address to its
     * prefix: a ledger keyed on the bare address would hand an attacker a
     * fresh ladder on every hop inside the /64 the block already covers,
     * which is the same reasoning detect() gives for its hit counter.
     *
     * Escalation improves a block; it is never a precondition for one. A
     * ledger that can't be read must not cost the block itself, so any
     * failure falls back to the flat duration and the address is still
     * blocked — and the log line is throttled, because a database that is
     * refusing writes will refuse one per offender for a whole tick.
     *
     * The offence is recorded before block() rather than after it, because
     * the count is what decides the duration block() is given. Two things
     * follow, both accepted:
     *
     * An address the never_* lists refuse still records an offence, since
     * block() below is what throws. That costs one row, which decay prunes,
     * and nothing ever reads it: an address that is always refused never
     * gets a block for the ladder to lengthen.
     *
     * And if block() fails for some other reason — a transient write error,
     * a race on its own unique index — the count is left one ahead of the
     * blocks actually issued, so a later block is one rung longer than the
     * history strictly earned. That needs the database healthy enough to
     * write the ledger and then failing on blacklisted_ips, it errs towards
     * blocking rather than away from it, and it decays. The alternatives are
     * worse: block() dispatches IpBlocked and queues the sync push, so a
     * transaction spanning both would have listeners acting on a block a
     * rollback then removed.
     */
    private function escalatedMinutes(string $ip, string $scope, int $durationMinutes): int
    {
        try {
            return $this->offences->durationFor(
                $this->blacklist->normalizeTarget($ip),
                $scope,
                $durationMinutes,
            );
        } catch (\Throwable $e) {
            if (! FailureWindow::isOpen('escalation-ledger')) {
                FailureWindow::open('escalation-ledger');

                Log::channel(config('watchtower.log_channel', 'stack'))
                    ->error('Watchtower: the offence ledger failed, so this block fell back to the flat duration', [
                        'error' => $e->getMessage(),
                    ]);
            }

            return $durationMinutes;
        }
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

        // Blocked, or already decided and held back — see holdDecision(). A
        // warn-mode rule never blocks, so without the hold nothing ever takes
        // an address out of play and it is re-reported on every tick its rows
        // stay inside the window: ~1,440 lines a day for one address, and a
        // live dry run that disagrees with `watchtower:simulate` by roughly
        // the block duration.
        $holder = $this->ruleHolder($level, $messageContains, $threshold, $windowMinutes, $scope);
        $settled = fn (string $ip): bool => $this->blacklist->isBlocked($ip)
            || $this->blockedInScope($ip, $scope)
            || $this->ruleHeld($holder, $ip, $mode);

        // Dropped before the user-count query so it isn't computed for
        // addresses that are already settled — their rows keep matching for
        // the rest of the window, so they reappear on every tick. Still
        // re-checked in the loop below, because blocking or holding one IPv6
        // address covers its whole prefix and can settle a later offender
        // mid-loop.
        $offenders = $query->pluck('ip_address')->reject($settled)->values();

        if ($offenders->isEmpty()) {
            return;
        }

        $distinctUsers = $this->distinctUsersPerIp($logsTable, $offenders->all(), $windowStart);

        $reason = sprintf(
            'Auto-blocked: %s%s exceeded %d hits in %d min',
            $level ? "level={$level} " : '',
            $messageContains ? "contains='{$messageContains}' " : '',
            $threshold,
            $windowMinutes,
        );

        foreach ($offenders as $ip) {
            if ($settled($ip)) {
                continue;
            }

            $users = $distinctUsers[$ip] ?? 0;

            $context = [
                'rule_index'     => $ruleIndex,
                'rule'           => $rule,
                'threshold'      => $threshold,
                'window_minutes' => $windowMinutes,
            ];

            $heldBy = $this->blockOrReport($ip, $reason, $mode, $scope, $users, $sharedIpThreshold, $durationMinutes, $context);

            try {
                $this->holdDecision($holder, $this->blacklist->normalizeTarget($ip), $mode, $heldBy, $durationMinutes);
            } catch (\Throwable $e) {
                // Unheld, so reported again next tick — the behaviour before
                // the hold existed, and better than losing the rules after it.
                $this->reportRuleHoldFailure($e);
            }
        }
    }

    /**
     * isHeld() for a rule, failing open to "not held".
     *
     * The hold is the only cache a warn-mode rule touches — isBlocked() reads
     * the table and the report is a log line — so without this a cache outage
     * would throw out of run() and take every later rule's dry run with it.
     * Not held means reported again, which is what a rule did before it had a
     * hold at all. The detector path needs none of this: record() already
     * fails open around the whole decision.
     */
    private function ruleHeld(string $holder, string $ip, string $mode): bool
    {
        try {
            return $this->isHeld($holder, $this->blacklist->normalizeTarget($ip), $ip, $mode);
        } catch (\Throwable $e) {
            $this->reportRuleHoldFailure($e);

            return false;
        }
    }

    /**
     * Once per window, not per offender per tick — see reportDetectorFailure().
     */
    private function reportRuleHoldFailure(\Throwable $e): void
    {
        if (FailureWindow::isOpen('rule-hold')) {
            return;
        }

        FailureWindow::open('rule-hold');

        try {
            Log::channel(config('watchtower.log_channel', 'stack'))
                ->error('Watchtower: a rule could not read or write its hold, so it reported without one', [
                    'error' => $e->getMessage(),
                ]);
        } catch (\Throwable) {
            // A broken log channel must not undo the fail-open.
        }
    }

    /**
     * The name a rule's hold is kept under, from the fields that decide what
     * it matches and where it would block.
     *
     * Not its index: rules have no name, and an index shifts when a rule
     * above it is added or removed, which would hand one rule's hold to
     * another. Editing any of these fields makes it a different rule, whose
     * first crossing is then reported afresh — the right answer for a rule
     * whose matches may no longer be the same ones. Scope is in it so two
     * rules matching the same rows for different route groups don't answer
     * for each other. Mode is deliberately not
     * part of it: the hold records the mode it was opened under, so arming a
     * rule takes effect on the next tick. See HitWindow::openNotionalBlock().
     */
    private function ruleHolder(mixed $level, mixed $messageContains, int $threshold, int $windowMinutes, string $scope): string
    {
        // `?: null` because applyRule() applies both filters by truthiness, so
        // unset, '' and 0 all mean "no filter" and must not read as three rules.
        return 'rule:'.hash('xxh128', serialize([$level ?: null, $messageContains ?: null, $threshold, $windowMinutes, $scope]));
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
