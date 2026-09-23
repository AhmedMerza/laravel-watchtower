<?php

declare(strict_types=1);

namespace Watchtower\Support;

/**
 * The scanner-path patterns, compiled once into one regex.
 *
 * `Str::is()` — and so `$request->is()` — loops the pattern list and builds a
 * fresh regex for each entry on every call: preg_quote, a str_replace to turn
 * `*` into `.*`, then its own preg_match. With the seven patterns that ship by
 * default that is seven regex builds and seven matches on every request the
 * detector middleware sees, matching or not. One anchored alternation answers
 * the same question with one match.
 *
 * This mirrors what UserAgentFilter already does for its deny list, including
 * why the memo is keyed on the source array rather than built once: a config
 * change — a test's `config()->set()`, a runtime override — has to take effect
 * instead of being masked by a stale compile. That keying is also what makes a
 * static safe, since nothing can serve a regex the current patterns didn't
 * produce.
 *
 * ⚠️ The compiled form must stay equivalent to `Str::is($patterns, $path, true)`,
 * which is what this replaced. PathMatcherTest asserts that directly over a
 * corpus rather than trusting the transformation by eye — this is the matcher
 * that decides whether a request is a scanner probe, so a quiet drift here is
 * a security bug, not a formatting one.
 */
final class PathMatcher
{
    /**
     * The patterns last compiled, alongside the regex they produced.
     *
     * @var array{0: array<mixed>, 1: string|null}|null
     */
    private static ?array $compiled = null;

    /**
     * Whether $path matches any of $patterns, which are `*`-wildcard globs as
     * an operator wrote them, with or without a leading slash.
     *
     * @param  array<mixed>  $patterns
     */
    public static function matchesAny(array $patterns, string $path): bool
    {
        $regex = self::regex($patterns);

        // === 1 rather than a truthy check: preg_match returns false on a
        // malformed UTF-8 subject, and a scanner controls the path.
        return $regex !== null && preg_match($regex, $path) === 1;
    }

    /**
     * The patterns as one case-insensitive anchored regex, or null when there
     * are none to match.
     *
     * @param  array<mixed>  $patterns
     */
    public static function regex(array $patterns): ?string
    {
        if (self::$compiled !== null && self::$compiled[0] === $patterns) {
            return self::$compiled[1];
        }

        $parts = [];

        foreach ($patterns as $pattern) {
            if (! is_scalar($pattern)) {
                continue;
            }

            // ltrim because the patterns read better in config with a leading
            // slash, while decodedPath() has none. preg_quote because they are
            // globs, not regexes — a `.` must match a literal dot, and an
            // unbalanced bracket must not break the whole expression. Only
            // then is `\*` reopened into `.*`, which is exactly the pair of
            // steps Str::is() performs per pattern.
            $parts[] = str_replace('\*', '.*', preg_quote(ltrim((string) $pattern, '/'), '#'));
        }

        // `iu` matches Str::is()'s flags when told to ignore case: scanners
        // vary case precisely to slip past naive matching, and `/WP-ADMIN/`
        // is the same probe as `/wp-admin/`.
        $regex = $parts === [] ? null : '#^(?:'.implode('|', $parts).')\z#iu';

        self::$compiled = [$patterns, $regex];

        return $regex;
    }
}
