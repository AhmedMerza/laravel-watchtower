<?php

declare(strict_types=1);

namespace Watchtower\Services;

use Illuminate\Contracts\Cache\Repository;
use Illuminate\Support\Facades\Cache;
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
     *                           verification. Null skips verification: with
     *                           no address there is nothing to resolve, and
     *                           a claim we cannot check is not a claim we
     *                           should punish.
     */
    public function reject(string $agent, ?string $ip): ?string
    {
        // Allow wins over deny, so a pentest you are running yourself gets
        // through by naming its User-Agent here rather than by editing the
        // deny list and losing the protection for everyone else.
        if ($this->firstMatch('allow', $agent) !== null) {
            return null;
        }

        $bot = $this->claimedSearchBot($agent);

        if ($bot !== null) {
            // A verified crawler is genuine and skips the deny list
            // entirely; an unverified one is something pretending to be
            // Google, which is a stronger signal than any name on the list.
            return $this->verified($bot, $ip) ? null : "unverified {$bot}";
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
     * Both outcomes are cached, which is what holds each address to one DNS
     * round-trip per TTL: caching only the successes would hand anyone
     * spoofing Googlebot a free resolver lookup on every request.
     *
     * Fails open at every step a resolver or cache can fail, because the
     * whole feature is noise reduction — losing it for a TTL is a far
     * better outcome than a slow resolver adding its timeout to every
     * request, or a cold cache turning a spoofing run into a DNS flood.
     */
    private function verified(string $bot, ?string $ip): bool
    {
        if ($ip === null) {
            return true;
        }

        $settings = (array) config('watchtower.user_agents.verify_search_bots', []);
        $prefix = (string) config('watchtower.cache.key', 'watchtower:blacklist');
        $key = "{$prefix}:ua:bot:{$bot}:{$ip}";

        try {
            $cache = $this->cache();
            $cached = $cache->get($key);

            if (is_bool($cached)) {
                return $cached;
            }

            $verdict = $this->resolve(
                $ip,
                (array) (($settings['bots'] ?? [])[$bot] ?? []),
            );

            $cache->put($key, $verdict, max(1, (int) ($settings['cache_hours'] ?? 24)) * 3600);

            return $verdict;
        } catch (\Throwable) {
            // With the cache unavailable we cannot promise one lookup per
            // TTL, so we don't look up at all.
            return true;
        }
    }

    /**
     * @param  list<string>|array<array-key, string>  $domains
     */
    private function resolve(string $ip, array $domains): bool
    {
        $host = $this->reverseLookup($ip);

        // gethostbyaddr() hands back the address itself when there is no
        // PTR record, which is not a hostname and must not be compared as
        // one.
        if ($host === null || $host === $ip) {
            return false;
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

        foreach ($this->forwardLookup($host, str_contains($ip, ':')) as $address) {
            if ($canonical !== null && IpRange::canonical($address) === $canonical) {
                return true;
            }
        }

        return false;
    }

    /**
     * The PTR hostname for an address, or null when there isn't one.
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
     * Every address a hostname resolves to, in the family being verified.
     *
     * @return list<string>
     */
    protected function forwardLookup(string $host, bool $ipv6): array
    {
        if ($ipv6) {
            $records = @dns_get_record($host, DNS_AAAA);

            return $records === false ? [] : array_values(array_filter(array_map(
                static fn (array $record): string => (string) ($record['ipv6'] ?? ''),
                $records,
            )));
        }

        $addresses = @gethostbynamel($host);

        return $addresses === false ? [] : $addresses;
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
