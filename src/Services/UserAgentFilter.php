<?php

declare(strict_types=1);

namespace Watchtower\Services;

use Illuminate\Cache\RateLimiter;
use Illuminate\Contracts\Cache\Repository;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Log;
use Watchtower\Support\FailureWindow;
use Watchtower\Support\IpRange;

/**
 * Decides whether a request's User-Agent names a known attack tool.
 *
 * The client writes its own User-Agent, so this is not a security boundary
 * and is not meant to be one — sqlmap, Nikto and WPScan each change theirs
 * with a single flag. What it removes is the background noise: unattended
 * scanners running defaults, which is most of what actually reaches a
 * production app. It costs one regex match against a literal alternation,
 * with no cache read and no DB read.
 *
 * Because it is spoofable, a match rejects THE REQUEST and nothing more. It
 * never blocks the address on its own; that only happens when the
 * `bad_user_agent` detector is armed — off by default — and then through
 * the same guards every other detector answers to.
 */
class UserAgentFilter
{
    /**
     * How long a "the resolver could not answer" verdict is cached for.
     *
     * Far shorter than `cache_hours`, because that verdict is ambiguous:
     * gethostbyaddr() returns the address unchanged both when there is
     * genuinely no PTR record and when the resolver simply failed to
     * answer, and the two are indistinguishable. Cached for a full day, a
     * momentary resolver blip would tell a real crawler to go away for a
     * day. A definitive answer — a PTR that exists and doesn't match, or
     * doesn't resolve back — is cached for the full TTL.
     */
    private const UNRESOLVED_TTL = 300;

    /**
     * The compiled `allow` and `deny` regexes, each kept alongside the
     * patterns it was built from.
     *
     * The service is a singleton, so this compiles once per worker under
     * Octane rather than once per request. Keying on the source array rather
     * than compiling in the constructor is what lets a config change — a
     * test's `config()->set()`, a runtime override — take effect instead of
     * being masked by a stale compile.
     *
     * @var array<string, array{0: list<string>, 1: string|null}>
     */
    private array $compiled = [];

    /**
     * Why this request should be rejected, or null to let it through.
     *
     * The string is the text that actually matched (`sqlmap`), or
     * `unverified <bot>` when a request claiming to be a search engine
     * failed its DNS check. It exists for the log line and for the
     * per-rule counts in #20; nothing branches on it.
     *
     * @param  string  $agent  the request's User-Agent, already known non-empty
     * @param  string|null  $ip  the canonical client address, for search-bot
     *                           verification
     */
    public function reject(string $agent, ?string $ip): ?string
    {
        // Allow wins over deny, so a pentest you are running yourself gets
        // through by naming its User-Agent here rather than by editing the
        // deny list and losing the protection for everyone else.
        if ($this->firstMatch('allow', $agent) !== null) {
            return null;
        }

        // Only consider the search-bot branch when there is an address to
        // resolve. Without one the claim can be neither confirmed nor
        // disproved — and treating "unverifiable" as "verified" would let
        // this branch swallow the deny list entirely, so a User-Agent of
        // `sqlmap Googlebot` would sail past a list that names sqlmap.
        // Unverifiable means "judge it like any other User-Agent", not
        // "let it through".
        if ($ip !== null) {
            $bot = $this->claimedSearchBot($agent);

            if ($bot !== null) {
                // A verified crawler is genuine and skips the deny list
                // entirely; an unverified one is something pretending to be
                // Google, which is a stronger signal than any name on the
                // list.
                return $this->verified($bot, $ip) ? null : "unverified {$bot}";
            }
        }

        return $this->firstMatch('deny', $agent);
    }

    /**
     * The first `deny`/`allow` pattern this User-Agent contains, as it
     * appears in the agent itself.
     */
    private function firstMatch(string $which, string $agent): ?string
    {
        $regex = $this->regex($which);

        if ($regex === null) {
            return null;
        }

        // `=== 1` and not a truthiness check: preg_match() returns false on
        // a runtime error (a backtrack limit, a bad UTF-8 sequence in the
        // header), and an error must let the request through rather than
        // reject everything. Fail open, the way the blocking middleware and
        // the detectors already do.
        return preg_match($regex, $agent, $matches) === 1 ? $matches[0] : null;
    }

    /**
     * The configured patterns compiled into one case-insensitive regex, or
     * null when there are none to match.
     */
    private function regex(string $which): ?string
    {
        $patterns = $this->patterns($which);
        $cached = $this->compiled[$which] ?? null;

        if ($cached !== null && $cached[0] === $patterns) {
            return $cached[1];
        }

        // preg_quote() every pattern: these are plain substrings, not
        // regexes. Quoting means a `.` in a config entry matches a literal
        // dot instead of anything, an unbalanced bracket can't break the
        // whole expression, and the alternation is all literals — so there
        // is no backtracking to run away with however long the header is.
        $regex = $patterns === []
            ? null
            : '#'.implode('|', array_map(
                static fn (string $pattern): string => preg_quote($pattern, '#'),
                $patterns,
            )).'#i';

        $this->compiled[$which] = [$patterns, $regex];

        return $regex;
    }

    /**
     * @return list<string>
     */
    private function patterns(string $which): array
    {
        return array_values(array_filter(
            array_map(
                static fn ($pattern): string => trim((string) $pattern),
                (array) config("watchtower.user_agents.{$which}", []),
            ),
            // An empty pattern compiles into an alternative that matches
            // every User-Agent there is, so one stray comma in an env list
            // would turn the whole internet into a scanner. Drop them.
            static fn (string $pattern): bool => $pattern !== '',
        ));
    }

    /**
     * The search engine this User-Agent claims to be, when verification is
     * switched on and it claims to be one.
     */
    private function claimedSearchBot(string $agent): ?string
    {
        $settings = (array) config('watchtower.user_agents.verify_search_bots', []);

        if (! ($settings['enabled'] ?? false)) {
            return null;
        }

        foreach (array_keys((array) ($settings['bots'] ?? [])) as $bot) {
            if (stripos($agent, (string) $bot) !== false) {
                return (string) $bot;
            }
        }

        return null;
    }

    /**
     * Forward-confirmed reverse DNS, cached per address.
     *
     * ⚠️ These are BLOCKING resolver calls on the request path, and PHP
     * gives them no timeout — how long they can take is the OS resolver's
     * `timeout`/`attempts` to decide, which can be tens of seconds against
     * a black-holed nameserver. They also fail by RETURNING FALSE rather
     * than throwing, so the try/catch below does not bound them. Three
     * things keep that from being a way to tie up the worker pool, and all
     * three matter:
     *
     * - Both outcomes are cached, not just the successes — otherwise
     *   anyone spoofing Googlebot would get a free resolver lookup on
     *   every request of a scan.
     * - The key is the address a BLOCK would cover, not the bare address.
     *   Keyed per address, one attacker-owned IPv6 /64 is billions of
     *   distinct cache misses, each a fresh lookup and a fresh cache entry.
     * - Lookups are capped per minute across the whole app, so the very
     *   worst case is a bounded number of workers waiting on DNS rather
     *   than all of them.
     *
     * It is off by default for these reasons, and wants a local caching
     * resolver in front of it.
     */
    private function verified(string $bot, string $ip): bool
    {
        $settings = (array) config('watchtower.user_agents.verify_search_bots', []);
        $prefix = (string) config('watchtower.cache.key', 'watchtower:blacklist');

        // The same target AutoBlockService counts against, for the same
        // reason: an IPv6 client controls its whole /64 and can move
        // anywhere inside it.
        $target = IpRange::blockTarget($ip) ?? $ip;

        try {
            $cache = $this->cache();
            $cached = $cache->get("{$prefix}:ua:bot:{$bot}:{$target}");

            if (is_bool($cached)) {
                return $cached;
            }

            if (! $this->withinLookupBudget($cache, $prefix, $settings)) {
                // Over budget: trust the claim and write nothing, so it is
                // verified properly once there is budget again. Detection
                // is never worth the app itself.
                return true;
            }

            $verdict = $this->resolve($ip, (array) (($settings['bots'] ?? [])[$bot] ?? []));

            $cache->put(
                "{$prefix}:ua:bot:{$bot}:{$target}",
                $verdict === true,
                $verdict === null
                    ? self::UNRESOLVED_TTL
                    : max(1, (int) ($settings['cache_hours'] ?? 24)) * 3600,
            );

            return $verdict === true;
        } catch (\Throwable $e) {
            // With the cache unavailable we cannot promise a bounded number
            // of lookups, so we don't look up at all.
            $this->reportVerificationFailure($e);

            return true;
        }
    }

    /**
     * Whether the app has resolver budget left this minute.
     *
     * A cap on how much of the worker pool can be sitting in a DNS call at
     * once. `0` switches it off, the way `shared_ip_user_threshold` does.
     *
     * @param  array<string, mixed>  $settings
     */
    private function withinLookupBudget(Repository $cache, string $prefix, array $settings): bool
    {
        $max = (int) ($settings['max_lookups_per_minute'] ?? 30);

        if ($max <= 0) {
            return true;
        }

        return (new RateLimiter($cache))->hit("{$prefix}:ua:bot:lookups", 60) <= $max;
    }

    /**
     * True when the claim checks out, false when it is definitively wrong,
     * and null when the resolver could not answer at all.
     *
     * @param  array<array-key, string>  $domains
     */
    private function resolve(string $ip, array $domains): ?bool
    {
        $host = $this->reverseLookup($ip);

        // gethostbyaddr() hands back the address unchanged when it cannot
        // answer — which covers both "this address has no PTR record" and
        // "the resolver did not respond", indistinguishably. Neither is a
        // hostname, and neither is a definitive "this is not Googlebot",
        // so the verdict is cached only briefly.
        if ($host === null || $host === $ip) {
            return null;
        }

        $host = rtrim(strtolower($host), '.');

        if (! $this->underAnyDomain($host, $domains)) {
            return false;
        }

        // The forward half is the half that matters: a PTR record is set by
        // whoever controls the address, so anyone can point one at
        // googlebot.com. Only Google can make googlebot.com resolve back.
        return $this->forwardConfirms($host, $ip);
    }

    /**
     * @param  array<array-key, string>  $domains
     */
    private function underAnyDomain(string $host, array $domains): bool
    {
        foreach ($domains as $domain) {
            // Leading dots read naturally in config (`.googlebot.com`) and
            // mean the same thing here.
            $domain = strtolower(trim((string) $domain, " \t\n\r\0\x0B."));

            // The dot in the suffix test is load-bearing: without it
            // `notgooglebot.com` passes as `googlebot.com`.
            if ($domain !== '' && ($host === $domain || str_ends_with($host, '.'.$domain))) {
                return true;
            }
        }

        return false;
    }

    private function forwardConfirms(string $host, string $ip): bool
    {
        $canonical = IpRange::canonical($ip);

        if ($canonical === null) {
            return false;
        }

        $ipv6 = str_contains($ip, ':');

        foreach ($this->addressesFrom($this->forwardLookup($host, $ipv6), $ipv6) as $address) {
            if (IpRange::canonical($address) === $canonical) {
                return true;
            }
        }

        return false;
    }

    /**
     * Pull the addresses out of whatever the resolver handed back.
     *
     * The two lookups have different shapes — gethostbynamel() returns a
     * flat list of addresses, dns_get_record() a list of record arrays — and
     * both return false when they cannot answer. Kept apart from the lookup
     * itself so this mapping is exercised by tests rather than mocked away
     * with it: a typo in the `ipv6` key would otherwise fail every IPv6
     * crawler silently, which reads exactly like a spoofer.
     *
     * @return list<string>
     */
    private function addressesFrom(array|false $records, bool $ipv6): array
    {
        if ($records === false) {
            return [];
        }

        if (! $ipv6) {
            return array_values(array_map(strval(...), $records));
        }

        return array_values(array_filter(
            array_map(
                static fn ($record): string => is_array($record) ? (string) ($record['ipv6'] ?? '') : '',
                $records,
            ),
            static fn (string $address): bool => $address !== '',
        ));
    }

    /**
     * The PTR hostname for an address, or null when the lookup was refused.
     *
     * Protected, and doing nothing but the lookup, so tests can stand in for
     * the resolver without reaching the network.
     */
    protected function reverseLookup(string $ip): ?string
    {
        $host = @gethostbyaddr($ip);

        return $host === false ? null : $host;
    }

    /**
     * The raw forward lookup, in the family being verified. Returns the
     * resolver's own shape — see addressesFrom(), which unpacks it.
     *
     * @return array<array-key, mixed>|false
     */
    protected function forwardLookup(string $host, bool $ipv6): array|false
    {
        return $ipv6 ? @dns_get_record($host, DNS_AAAA) : @gethostbynamel($host);
    }

    /**
     * Log the failure at most once per window, the way every other fail-open
     * path in this package does.
     *
     * Without it, a cache backend that is down means search-bot
     * verification silently degrades to "trust every claim" for the whole
     * outage, with nothing anywhere to say so.
     */
    private function reportVerificationFailure(\Throwable $e): void
    {
        if (FailureWindow::isOpen('user_agent_verify')) {
            return;
        }

        FailureWindow::open('user_agent_verify');

        try {
            Log::channel(config('watchtower.log_channel', 'stack'))
                ->error('Watchtower: search-bot verification failed, trusting the claim', [
                    'error' => $e->getMessage(),
                ]);
        } catch (\Throwable) {
            // A broken log channel must not undo the fail-open.
        }
    }

    /**
     * Resolved per call so a runtime config change takes effect, matching
     * BlacklistCache and HitWindow.
     */
    private function cache(): Repository
    {
        $store = config('watchtower.cache.store');

        return Cache::store(is_string($store) ? $store : null);
    }
}
