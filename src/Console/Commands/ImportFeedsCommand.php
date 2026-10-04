<?php

declare(strict_types=1);

namespace Watchtower\Console\Commands;

use Illuminate\Console\Command;
use Illuminate\Contracts\Cache\Repository;
use Illuminate\Database\UniqueConstraintViolationException;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Str;
use Symfony\Component\HttpFoundation\IpUtils;
use Watchtower\Enums\BlockSource;
use Watchtower\Events\IpUnblocked;
use Watchtower\Models\BlacklistedIp;
use Watchtower\Services\BlacklistCache;
use Watchtower\Support\BlockScope;
use Watchtower\Support\IpRange;

/**
 * Imports public blocklists (Spamhaus DROP, FireHOL level1, …) as `feed`
 * blocks (#21).
 *
 * Every enabled feed is fetched in one run and the run reconciles all feed
 * rows against their UNION, not feed by feed. FireHOL level1 already contains
 * most of Spamhaus DROP, so a per-feed replace would have one feed delete a
 * range the other still lists, unblocking it until that feed's next run.
 *
 * Feed rows are local: no IpBlocked event (so no webhook, no target push),
 * and the sync export and watchtower:reconcile both leave them out. Every
 * environment imports the feeds itself. A master's synced block for the same
 * address replaces a feed row (BlacklistService::applySync()), and from then
 * on it is a sync row like any other.
 */
class ImportFeedsCommand extends Command
{
    protected $signature = 'watchtower:import-feeds
        {--force : Accept a feed that shrank by more than half since its last import}';

    protected $description = 'Import the enabled public blocklists, replacing every previously imported feed entry';

    /**
     * IANA special-purpose ranges (RFC 6890 and successors). A feed range
     * overlapping any of these is dropped whole: FireHOL level1 lists the
     * bogons, which cover RFC 1918, and importing them as-is would block the
     * app's own load balancer, health checks and queue workers.
     */
    private const RESERVED = [
        '0.0.0.0/8', '10.0.0.0/8', '100.64.0.0/10', '127.0.0.0/8', '169.254.0.0/16',
        '172.16.0.0/12', '192.0.0.0/24', '192.0.2.0/24', '192.88.99.0/24', '192.168.0.0/16',
        '198.18.0.0/15', '198.51.100.0/24', '203.0.113.0/24', '224.0.0.0/4', '240.0.0.0/4',
        '::/128', '::1/128', '64:ff9b::/96', '64:ff9b:1::/48', '100::/64', '2001::/23',
        '2001:db8::/32', '2002::/16', 'fc00::/7', 'fe80::/10', 'ff00::/8',
    ];

    /**
     * The widest range a feed may add. The real feeds' widest legitimate
     * entries are an IPv4 /12 and an IPv6 /29; these leave 4x and 32x
     * headroom over them. Wider is a broken or compromised list.
     */
    private const MIN_IPV4_PREFIX = 10;

    private const MIN_IPV6_PREFIX = 24;

    /**
     * The most address space one feed may cover. A floor on single entries
     * doesn't bound a list of many of them. The real feeds cover at most
     * 0.42% of IPv4 (FireHOL level1, 18M addresses) and ~2^39.5 IPv6 /64s
     * (DROP v6); these allow ~7x and ~23x that. A feed above either is
     * refused whole, as a bad download is.
     */
    private const MAX_IPV4_ADDRESSES = 2 ** 27;

    private const MAX_IPV6_NETWORKS = 2 ** 44;

    /**
     * The most entries one feed may list. The coverage cap above counts
     * addresses, so it lets through millions of single IPs — each its own
     * row and cache key. The real feeds list under 5,000; this allows ~20x.
     */
    private const MAX_ENTRIES = 100_000;

    /** A feed shrinking below this share of its previous size is treated as a bad download. */
    private const MIN_KEPT_SHARE = 0.5;

    public function __construct(private readonly BlacklistCache $cache)
    {
        parent::__construct();
    }

    public function handle(): int
    {
        $configured = (array) config('watchtower.feeds', []);
        $feeds = array_filter($configured, fn ($feed) => ! empty($feed['enabled']));

        // A feed turned off forgets its size, so turning it back on (or
        // pointing it at a smaller list) isn't refused against a stale one.
        foreach (array_diff_key($configured, $feeds) as $name => $_) {
            $this->counts()->forget($this->countKey((string) $name));
        }

        $owned = BlacklistedIp::where('source', BlockSource::Feed)
            ->selectRaw('blocked_by, count(*) as total')
            ->groupBy('blocked_by')
            ->pluck('total', 'blocked_by');

        $wanted = [];
        $listed = [];
        $complete = true;

        foreach ($feeds as $name => $feed) {
            $targets = $this->fetch((string) $name, (array) ($feed['urls'] ?? []));

            // The size it last listed, not the rows attributed to it: a range
            // two feeds list is attributed to the first, so with both shipped
            // feeds on, FireHOL owns only what DROP lacks, and comparing
            // against that would wave a truncated download through. Rows
            // owned are the fallback for a first run or a flushed cache.
            $previous = (int) ($this->counts()->get($this->countKey((string) $name)) ?? $owned["feed:{$name}"] ?? 0);

            if ($targets !== null && ! $this->option('force') && count($targets) < $previous * self::MIN_KEPT_SHARE) {
                $this->skip($name, 'it listed '.count($targets)." usable ranges, down from {$previous} (if the list really did shrink, run watchtower:import-feeds --force once)");
                $targets = null;
            }

            if ($targets === null) {
                $complete = false;

                continue;
            }

            $listed[$name] = count($targets);

            foreach ($targets as $target) {
                $wanted[$target] ??= (string) $name;
            }
        }

        [$added, $removed, $lapsed] = DB::transaction(fn () => $this->apply($wanted, $complete));

        // As watchtower:cleanup does for the same rows: a block target
        // (cloudflare, nginx_file) that was pushed the lapsed temporary block
        // only lifts it on IpUnblocked, and the feed row taking its place is
        // never pushed — so without this the edge rule would never lift.
        foreach ($lapsed as $ip) {
            event(new IpUnblocked($ip));
        }

        foreach ($listed as $name => $count) {
            $this->counts()->forever($this->countKey((string) $name), $count);
        }

        if (! $this->cache->rebuild()) {
            $this->error("Imported feeds ({$added} added, {$removed} removed), but the cache rebuild failed — its DB read error is on the watchtower log channel.");

            return self::FAILURE;
        }

        $kept = $complete ? '' : ' Nothing was removed, because a feed failed — see above.';
        $this->info('Imported '.count($feeds)." feed(s): {$added} added, {$removed} removed, ".count($wanted)." listed.{$kept}");

        return $complete ? self::SUCCESS : self::FAILURE;
    }

    /**
     * Every usable target one feed lists, canonical and deduplicated — or
     * null if any of its URLs failed or it listed nothing usable.
     *
     * @param  list<string>  $urls
     * @return list<string>|null
     */
    private function fetch(string $name, array $urls): ?array
    {
        $targets = [];

        foreach ($urls as $url) {
            // A feed decides what gets blocked, so it is only read over TLS,
            // and a redirect may not step down to plain http.
            if (! str_starts_with(strtolower((string) $url), 'https://')) {
                $this->skip($name, "{$url} is not an https URL");

                return null;
            }

            try {
                $response = Http::timeout(30)
                    ->withOptions(['allow_redirects' => ['max' => 5, 'protocols' => ['https']]])
                    ->get($url);
            } catch (\Throwable $e) {
                $this->skip($name, "{$url} could not be fetched: {$e->getMessage()}");

                return null;
            }

            if (! $response->successful()) {
                $this->skip($name, "{$url} returned HTTP {$response->status()}");

                return null;
            }

            foreach (self::parse($response->body()) as $target) {
                $targets[$target] = true;
            }
        }

        if ($targets === []) {
            $this->skip($name, 'it listed no usable ranges');

            return null;
        }

        if (count($targets) > self::MAX_ENTRIES) {
            $this->skip($name, 'it listed '.count($targets).' entries, more than the '.self::MAX_ENTRIES.' any real blocklist comes near');

            return null;
        }

        $ipv4 = 0;
        $ipv6 = 0;

        foreach (array_keys($targets) as $target) {
            [$address, $length] = IpRange::split((string) $target);

            if (str_contains($address, ':')) {
                $ipv6 += 2 ** (64 - min($length, 64));
            } else {
                $ipv4 += 2 ** (32 - $length);
            }
        }

        if ($ipv4 > self::MAX_IPV4_ADDRESSES || $ipv6 > self::MAX_IPV6_NETWORKS) {
            $this->skip($name, sprintf('it covers %.1f%% of IPv4 and %s IPv6 /64s, far more than any real blocklist', $ipv4 / 2 ** 32 * 100, number_format($ipv6)));

            return null;
        }

        return array_keys($targets);
    }

    /**
     * The usable targets in one feed file: the first IP or CIDR on each line
     * that isn't a comment, which reads both a plain netset (FireHOL) and
     * Spamhaus' one-JSON-object-per-line format without knowing which it
     * has. Reserved and implausibly wide ranges are dropped here.
     *
     * @return list<string>
     */
    public static function parse(string $body): array
    {
        $targets = [];

        foreach (preg_split('/\R/', $body) ?: [] as $line) {
            // JSON may escape the slash ("1.10.16.0\\/20"), which would
            // otherwise cut the prefix off and import the bare network address.
            $line = str_replace('\\/', '/', trim($line));

            if ($line === '' || $line[0] === '#' || $line[0] === ';') {
                continue;
            }

            preg_match_all('/[0-9A-Fa-f:.]+(?:\/\d+)?/', $line, $tokens);

            foreach ($tokens[0] as $token) {
                $target = IpRange::canonical($token);

                if ($target !== null) {
                    if (self::usable($target)) {
                        $targets[] = $target;
                    }

                    break;
                }
            }
        }

        return $targets;
    }

    private static function usable(string $target): bool
    {
        [$address, $length] = IpRange::split($target);

        if ($length < (str_contains($address, ':') ? self::MIN_IPV6_PREFIX : self::MIN_IPV4_PREFIX)) {
            return false;
        }

        foreach (self::RESERVED as $reserved) {
            // Two CIDR ranges overlap exactly when one holds the other's
            // first address.
            if (IpUtils::checkIp($address, $reserved) || IpUtils::checkIp(IpRange::split($reserved)[0], $target)) {
                return false;
            }
        }

        return true;
    }

    /**
     * Add what's newly listed and, only when every feed came through, remove
     * feed rows nothing lists any more. Never touches a manual, auto or sync
     * row: an address already blocked another way keeps that block.
     *
     * @param  array<string, string>  $wanted  target => the first feed listing it
     * @return array{int, int, list<string>} added, removed, and the lapsed global rows replaced
     */
    private function apply(array $wanted, bool $complete): array
    {
        // Live rows, plus every feed row (a feed row never lapses). A lapsed
        // manual/auto/sync row blocks nothing, so it must not keep a listed
        // range out; it is deleted below to make way, as cleanup would.
        $existing = BlacklistedIp::where('scope', BlockScope::GLOBAL)
            ->where(fn ($query) => $query->whereNull('expires_at')
                ->orWhere('expires_at', '>', now())
                ->orWhere('source', BlockSource::Feed))
            ->pluck('source', 'ip');

        $stale = $complete
            ? $existing->filter(fn ($source, $ip) => $source === BlockSource::Feed && ! isset($wanted[$ip]))->keys()
            : collect();

        foreach ($stale->chunk(500) as $chunk) {
            BlacklistedIp::where('scope', BlockScope::GLOBAL)
                ->where('source', BlockSource::Feed)
                ->whereIn('ip', $chunk->all())
                ->delete();
        }

        $now = now();
        $rows = [];

        foreach (array_diff_key($wanted, $existing->all()) as $target => $feed) {
            $rows[] = [
                'id'         => (string) Str::ulid(),
                'ip'         => $target,
                'scope'      => BlockScope::GLOBAL,
                'reason'     => "Listed by the {$feed} feed",
                'source_env' => app()->environment(),
                'source'     => BlockSource::Feed->value,
                'blocked_by' => "feed:{$feed}",
                'created_at' => $now,
                'updated_at' => $now,
            ];
        }

        $added = 0;
        $lapsed = [];

        foreach (array_chunk($rows, 500) as $chunk) {
            $expired = BlacklistedIp::where('scope', BlockScope::GLOBAL)
                ->where('expires_at', '<=', now())
                ->whereIn('ip', array_column($chunk, 'ip'))
                ->pluck('ip')
                ->all();

            if ($expired !== []) {
                BlacklistedIp::where('scope', BlockScope::GLOBAL)->whereIn('ip', $expired)->delete();
                array_push($lapsed, ...$expired);
            }

            $added += $this->insert($chunk);
        }

        return [$added, $stale->count(), $lapsed];
    }

    /**
     * Insert one chunk. A manual or auto block for one of these targets,
     * landing since the existing rows were read, keeps its row: the chunk is
     * retried without it rather than rolling the whole import back.
     *
     * Not insertOrIgnore(): on MySQL that is INSERT IGNORE, which also turns
     * an invalid enum value or a truncation into a warning — an import run
     * before the `feed` migration would store rows with an empty source.
     *
     * @param  list<array<string, mixed>>  $chunk
     */
    private function insert(array $chunk): int
    {
        try {
            // A savepoint, so a failed insert leaves Postgres' outer
            // transaction usable for the retry.
            DB::transaction(fn () => BlacklistedIp::insert($chunk));

            return count($chunk);
        } catch (UniqueConstraintViolationException) {
            $taken = BlacklistedIp::where('scope', BlockScope::GLOBAL)
                ->whereIn('ip', array_column($chunk, 'ip'))
                ->pluck('ip')
                ->flip();

            $chunk = array_values(array_filter($chunk, fn ($row) => ! isset($taken[$row['ip']])));
            BlacklistedIp::insert($chunk);

            return count($chunk);
        }
    }

    /** Where each feed's last listed size is remembered, for the shrink guard. */
    private function counts(): Repository
    {
        return Cache::store(config('watchtower.cache.store'));
    }

    private function countKey(string $name): string
    {
        return config('watchtower.cache.key', 'watchtower:blacklist').":feeds:{$name}:listed";
    }

    private function skip(string $name, string $why): void
    {
        $this->warn("Feed [{$name}] skipped: {$why}. Its existing entries are kept.");
        Log::channel(config('watchtower.log_channel', 'stack'))
            ->warning("Watchtower: feed [{$name}] skipped, existing entries kept", ['reason' => $why]);
    }
}
