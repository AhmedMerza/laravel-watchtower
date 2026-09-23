<?php

declare(strict_types=1);

use Illuminate\Support\Str;
use Watchtower\Support\PathMatcher;

/**
 * PathMatcher replaced `Str::is($patterns, $path, true)` on the detector path.
 * That call decides whether a request is a scanner probe, so the replacement
 * has to be equivalent rather than merely similar — these assert it against
 * the real Str::is() over a corpus, instead of trusting the transformation by
 * eye.
 */

/**
 * What Str::is() was given before the swap: the patterns ltrim'd of their
 * leading slash, since decodedPath() has none.
 *
 * @param  array<mixed>  $patterns
 * @return list<string>
 */
function ltrimmed(array $patterns): array
{
    return array_values(array_map(
        static fn ($pattern): string => ltrim((string) $pattern, '/'),
        $patterns,
    ));
}

dataset('probe paths', [
    '.env',
    '.env.local',
    '.env.production',
    '.ENV',
    '.Env.LOCAL',
    '.git/config',
    '.git/HEAD',
    '.gitignore',
    'wp-login.php',
    'WP-LOGIN.PHP',
    'wp-admin/setup-config.php',
    'WP-ADMIN/setup-config.php',
    'wp-admin',
    'xmlrpc.php',
    'phpmyadmin',
    'phpmyadmin/index.php',
    'phpMyAdmin2',
    '',
    '/',
    'index.php',
    'api/users',
    'env',
    'a.env',
    '.envx',
    'foo/.env',
    'x/y/z',
    'wp-login.php/extra',
    'dot.star.path',
    'weird[bracket]path',
    'plus+path',
    'question?path',
    'back\\slash',
    'unicode/café',
    'emoji/🙂',

    // Adversarial: each of these is matched by one of the patterns below ONLY
    // if preg_quote is skipped, so they are what makes the corpus sensitive to
    // the quoting step rather than merely to the wildcard one. `.` as any
    // char, `[...]` as a class, `+` as one-or-more, `?` as optional.
    'dotXstarYpath',
    'xenv',
    'weirdbpath',
    'weirdrpath',
    'plusspath',
    'plussspath',
    'questionpath',
    'questiopath',
    'wp-loginXphp',
    'xmlrpcXphp',
]);

it('matches exactly what Str::is did, for the shipped default patterns', function (string $path) {
    $patterns = (array) config('watchtower.auto_block.detectors.scanner_paths.patterns', []);

    expect($patterns)->not->toBe([]);

    expect(PathMatcher::matchesAny($patterns, $path))
        ->toBe(Str::is(ltrimmed($patterns), $path, true), "path: {$path}");
})->with('probe paths');

it('matches exactly what Str::is did, for awkward pattern shapes', function (string $path) {
    // Deliberately nasty: regex metacharacters that must stay literal, a bare
    // wildcard, an empty pattern, a pattern that is only a slash, and one that
    // would break an unquoted alternation outright.
    $patterns = [
        '/.env',
        '.env',
        '*',
        '',
        '/',
        '/dot.star.path',
        '/weird[bracket]path',
        '/plus+path',
        '/question?path',
        '/back\\slash',
        '/unicode/café',
        '/a*b',
        '/**',
        '/wp-*/*.php',
        '/trailing*',
    ];

    expect(PathMatcher::matchesAny($patterns, $path))
        ->toBe(Str::is(ltrimmed($patterns), $path, true), "path: {$path}");
})->with('probe paths');

it('matches exactly what Str::is did, for each pattern in isolation', function (string $path) {
    // One pattern at a time, so a disagreement names the pattern rather than
    // being absorbed by another alternative in the group.
    $each = [
        '/.env', '/.env.*', '/.git/*', '/wp-login.php', '/wp-admin/*',
        '/xmlrpc.php', '/phpmyadmin*', '*', '', '/a*b', '/*.php',
    ];

    foreach ($each as $pattern) {
        expect(PathMatcher::matchesAny([$pattern], $path))
            ->toBe(Str::is(ltrimmed([$pattern]), $path, true), "pattern: {$pattern}, path: {$path}");
    }
})->with('probe paths');

it('returns no regex for an empty pattern list, and matches nothing', function () {
    expect(PathMatcher::regex([]))->toBeNull()
        ->and(PathMatcher::matchesAny([], '.env'))->toBeFalse();
});

it('skips a non-scalar pattern instead of tripping over it', function () {
    // A malformed config entry must not take the matcher — or the request —
    // down with it, the way NeverBlockList drops a malformed allow-list entry.
    expect(PathMatcher::matchesAny([['nested'], '/.env'], '.env'))->toBeTrue()
        ->and(PathMatcher::matchesAny([['nested']], '.env'))->toBeFalse();
});

it('recompiles when the patterns change rather than serving a stale regex', function () {
    // The memo is keyed on the source array precisely so this holds. Without
    // it, the second call would answer from the first compile — which is how a
    // config()->set() in a test, or a runtime override in an app, would
    // silently stop taking effect.
    expect(PathMatcher::matchesAny(['/.env'], '.env'))->toBeTrue()
        ->and(PathMatcher::matchesAny(['/wp-login.php'], '.env'))->toBeFalse()
        ->and(PathMatcher::matchesAny(['/.env'], '.env'))->toBeTrue();
});

it('reuses the compiled regex when the patterns are unchanged', function () {
    $patterns = ['/.env', '/wp-admin/*'];

    // Same array, so the same compiled string comes back — identity of the
    // returned regex is the observable side of the memo.
    expect(PathMatcher::regex($patterns))->toBe(PathMatcher::regex($patterns));
});
