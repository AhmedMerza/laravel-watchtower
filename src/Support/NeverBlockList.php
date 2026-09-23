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
    /**
     * Each list's raw config entries, paired with their canonical forms.
     *
     * Canonicalising an entry is an inet_pton/inet_ntop round trip, and the
     * request path asks this up to three times per request — BlockedIpMiddleware
     * and UserAgentMiddleware on every request, ScopedBlockMiddleware again on
     * a scoped route. Re-parsing the same operator-typed list on each of them
     * is work nobody asked for, and it grows with the list: an app that adds
     * carrier ranges to never_block pays it linearly, on every request.
     *
     * Keyed on the raw array rather than parsed once at boot, for the reason
     * UserAgentFilter::regex() gives: a config change — a test's
     * `config()->set()`, a runtime override — has to take effect rather than
     * be masked by a stale parse. That keying is also what makes a static safe
     * here, since nothing can serve a value the current config didn't produce.
     *
     * @var array<string, array{0: array<mixed>, 1: list<string>}>
     */
    private static array $canonical = [];

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

        return $target !== null && IpRange::coversCanonical(self::entries($key), $target);
    }

    /**
     * One list's entries, canonical and malformed ones dropped — parsed only
     * when the configured array is not the one already parsed. See $canonical.
     *
     * @return list<string>
     */
    private static function entries(string $key): array
    {
        $raw = (array) config($key, []);
        $cached = self::$canonical[$key] ?? null;

        if ($cached !== null && $cached[0] === $raw) {
            return $cached[1];
        }

        $canonical = [];

        foreach ($raw as $entry) {
            $value = is_scalar($entry) ? IpRange::canonical(trim((string) $entry)) : null;

            // Malformed entries are dropped rather than fatal: an operator
            // typo in one line of the allow-list must not take the list — or
            // the request — down with it.
            if ($value !== null) {
                $canonical[] = $value;
            }
        }

        self::$canonical[$key] = [$raw, $canonical];

        return $canonical;
    }
}
