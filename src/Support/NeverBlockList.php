<?php

declare(strict_types=1);

namespace Watchtower\Support;

/**
 * The two allow-lists, asked the same question from both sides of the engine.
 *
 * `BlacklistService` consults these to REFUSE a block; `RuleSimulator`
 * consults them to avoid reporting a would-be block the engine would have
 * refused. Those are opposite actions on one predicate, which is exactly
 * the shape that drifts when it is written twice — the failure issue #38
 * documents, one table over. So the predicate lives here and neither side
 * owns it.
 *
 * Each method answers for ONE list, deliberately. `BlacklistService` checks
 * never_block first and never_auto_block second so that it can throw the
 * more specific exception for each, and folding them together here would
 * take that distinction away from it. A caller that wants "would automation
 * be refused?" asks both — see `refusesAutoBlock()`.
 *
 * Pure reads, no side effects: that is what lets the simulator use this
 * without gaining a path into anything that writes.
 */
final class NeverBlockList
{
    /** Addresses nothing may block — not the UI, not automation, not sync. */
    public static function neverBlock(string $ip): bool
    {
        return self::covered($ip, 'watchtower.never_block');
    }

    /** Addresses automation may not block, though an admin still can. */
    public static function neverAutoBlock(string $ip): bool
    {
        return self::covered($ip, 'watchtower.never_auto_block');
    }

    /**
     * Would an auto-block of this address be refused, by either list?
     *
     * The question the auto-block engine's callers actually have. Both
     * lists stop automation; they differ only in what else they stop, and
     * `BlacklistService::block()` throws for either one.
     */
    public static function refusesAutoBlock(string $ip): bool
    {
        return self::neverBlock($ip) || self::neverAutoBlock($ip);
    }

    private static function covered(string $ip, string $key): bool
    {
        $target = IpRange::canonical($ip);

        return $target !== null && IpRange::covers((array) config($key, []), $target);
    }
}
