<?php

declare(strict_types=1);

namespace Watchtower\Console\Commands;

use Illuminate\Console\Command;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Str;
use Symfony\Component\HttpFoundation\IpUtils;
use Watchtower\Enums\BlockSource;
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
 * environment imports the feeds itself.
 */
class ImportFeedsCommand extends Command
{
    protected $signature = 'watchtower:import-feeds';

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
     * entries are an IPv4 /12 and an IPv6 /29; anything far wider is a
     * broken or compromised list, not a netblock.
     */
    private const MIN_IPV4_PREFIX = 8;

    private const MIN_IPV6_PREFIX = 16;

    /** A feed shrinking below this share of its previous size is treated as a bad download. */
    private const MIN_KEPT_SHARE = 0.5;

    public function __construct(private readonly BlacklistCache $cache)
    {
        parent::__construct();
    }

    public function handle(): int
    {
        $feeds = array_filter((array) config('watchtower.feeds', []), fn ($feed) => ! empty($feed['enabled']));

        $owned = BlacklistedIp::where('source', BlockSource::Feed)
            ->selectRaw('blocked_by, count(*) as total')
            ->groupBy('blocked_by')
            ->pluck('total', 'blocked_by');

        $wanted = [];
        $complete = true;

        foreach ($feeds as $name => $feed) {
            $targets = $this->fetch((string) $name, (array) ($feed['urls'] ?? []));
            $previous = (int) ($owned["feed:{$name}"] ?? 0);

            if ($targets !== null && count($targets) < $previous * self::MIN_KEPT_SHARE) {
                $this->skip($name, 'it listed '.count($targets)." usable ranges, down from {$previous}");
                $targets = null;
            }

            if ($targets === null) {
                $complete = false;

                continue;
            }

            foreach ($targets as $target) {
                $wanted[$target] ??= (string) $name;
            }
        }

        [$added, $removed] = DB::transaction(fn () => $this->apply($wanted, $complete));

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
            try {
                $response = Http::timeout(30)->get($url);
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
     * @return array{int, int}
     */
    private function apply(array $wanted, bool $complete): array
    {
        $existing = BlacklistedIp::where('scope', BlockScope::GLOBAL)->pluck('source', 'ip');

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

        foreach (array_chunk($rows, 500) as $chunk) {
            BlacklistedIp::insert($chunk);
        }

        return [count($rows), $stale->count()];
    }

    private function skip(string $name, string $why): void
    {
        $this->warn("Feed [{$name}] skipped: {$why}. Its existing entries are kept.");
        Log::channel(config('watchtower.log_channel', 'stack'))
            ->warning("Watchtower: feed [{$name}] skipped, existing entries kept", ['reason' => $why]);
    }
}
