<?php

declare(strict_types=1);

namespace Watchtower\Console\Commands;

use Illuminate\Console\Command;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use Illuminate\Support\Str;
use Watchtower\Enums\BlockSource;
use Watchtower\Models\BlacklistedIp;
use Watchtower\Services\BlacklistCache;
use Watchtower\Support\BlockScope;
use Watchtower\Support\IpRange;
use Watchtower\Support\NeverBlockList;

/**
 * Imports antonioribeiro/firewall's lists (#29): its `firewall` table and the
 * `blacklist` / `whitelist` arrays in config/firewall.php. Neither needs the
 * old package installed — the table is read with the query builder, and the
 * published config file runs none of its code.
 *
 * Blacklisted entries become permanent manual blocks. Whitelisted ones are
 * printed for never_block, which is what the old whitelist did (it won over
 * any block), rather than stored: never_block is config, so nothing here
 * can write to it.
 *
 * Rows are inserted directly, not through BlacklistService::block(): that
 * would overwrite a block watchtower already holds, drop the old row's
 * timestamps, and fire IpBlocked once per entry — a notification and a
 * target push for each of what can be thousands. One cache rebuild and one
 * reconcile cover them all instead.
 */
class ImportFirewallCommand extends Command
{
    /** Shared with the README, so an import can be found (or undone) by it. */
    public const REASON = 'Imported from antonioribeiro/firewall';

    protected $signature = 'watchtower:import-firewall
        {--commit : Write the blocks; without it, only report what would happen}';

    protected $description = 'Import blocks and allowlist entries from antonioribeiro/firewall';

    public function __construct(private readonly BlacklistCache $cache)
    {
        parent::__construct();
    }

    public function handle(): int
    {
        // target => [created_at, updated_at], earliest first-seen kept.
        $blocks = [];
        $allow = [];

        foreach ($this->entries() as [$entry, $whitelisted, $created, $updated, $fromConfig]) {
            [$targets, $why] = $this->expand($entry, $fromConfig);

            if ($why !== null) {
                $this->line("  skip   {$entry} — {$why}");

                continue;
            }

            foreach ($targets as $target) {
                if ($whitelisted) {
                    $allow[$target] = true;

                    continue;
                }

                // Blocked the way block() would store it: a lone IPv6
                // address widens to its prefix.
                $target = (string) IpRange::blockTarget($target);

                if (! isset($blocks[$target]) || $created < $blocks[$target][0]) {
                    $blocks[$target] = [$created, $updated];
                }
            }
        }

        $existing = BlacklistedIp::active()
            ->where('scope', BlockScope::GLOBAL)
            ->whereIn('ip', array_map('strval', array_keys($blocks)))
            ->pluck('ip')
            ->flip();

        $rows = [];

        foreach ($blocks as $target => [$created, $updated]) {
            $target = (string) $target;
            $why = match (true) {
                IpRange::covers(array_keys($allow), $target) => 'also whitelisted, and the old package let whitelisted addresses through',
                NeverBlockList::neverBlock($target)           => 'covered by never_block',
                IpRange::isTooBroad($target)                  => 'broader than /'.IpRange::MIN_IPV4_PREFIX.' (IPv4) or /'.IpRange::MIN_IPV6_PREFIX.' (IPv6); block it by hand with force if you meant it',
                isset($existing[$target])                     => 'already blocked',
                default                                       => null,
            };

            if ($why !== null) {
                $this->line("  skip   {$target} — {$why}");

                continue;
            }

            $this->line("  block  {$target}");
            $rows[] = [
                'id'         => (string) Str::ulid(),
                'ip'         => $target,
                'scope'      => BlockScope::GLOBAL,
                'reason'     => self::REASON,
                'source_env' => app()->environment(),
                'source'     => BlockSource::Manual->value,
                'created_at' => $created,
                'updated_at' => $updated,
            ];
        }

        $this->allowlist(array_keys($allow));

        if (! $this->option('commit')) {
            $this->info(count($rows).' block(s) would be imported. Nothing was written; run again with --commit to import them.');

            return self::SUCCESS;
        }

        DB::transaction(function () use ($rows) {
            foreach (array_chunk($rows, 500) as $chunk) {
                // A lapsed block for the same target holds the (ip, scope)
                // unique key without blocking anything; the permanent row
                // replaces it. Its edge rule, if any, stays right: the
                // reconcile below pushes the same target again.
                BlacklistedIp::where('scope', BlockScope::GLOBAL)
                    ->whereIn('ip', array_column($chunk, 'ip'))
                    ->delete();

                // Not insertOrIgnore(): on MySQL that is INSERT IGNORE, which
                // turns a truncation into a warning and a corrupt row.
                BlacklistedIp::insert($chunk);
            }
        });

        if (! $this->cache->rebuild()) {
            $this->error('Imported '.count($rows).' block(s), but the cache rebuild failed — its DB read error is on the watchtower log channel.');

            return self::FAILURE;
        }

        $this->info('Imported '.count($rows).' block(s).');

        return $rows === [] ? self::SUCCESS : $this->call('watchtower:reconcile');
    }

    /**
     * Every entry from both sources, as [entry, whitelisted, created_at, updated_at, from config].
     *
     * @return list<array{string, bool, string, string, bool}>
     */
    private function entries(): array
    {
        $now = (string) now();
        $entries = [];

        if (Schema::hasTable('firewall')) {
            foreach (DB::table('firewall')->orderBy('id')->get() as $row) {
                $entries[] = [
                    trim((string) $row->ip_address),
                    (bool) $row->whitelisted,
                    (string) ($row->created_at ?? $now),
                    (string) ($row->updated_at ?? $row->created_at ?? $now),
                    false,
                ];
            }
        }

        // Whitelist first: an address on both lists was let through.
        foreach (['whitelist' => true, 'blacklist' => false] as $key => $whitelisted) {
            foreach ((array) config("firewall.{$key}", []) as $entry) {
                if (is_scalar($entry)) {
                    $entries[] = [trim((string) $entry), $whitelisted, $now, $now, true];
                }
            }
        }

        return $entries;
    }

    /**
     * What one old entry blocks, as canonical targets, or why it can't be imported.
     *
     * The old package accepted, besides an IP or CIDR: a netmask
     * (`10.0.0.0/255.0.0.0`), a dash range (`10.0.0.1-10.0.0.255`), a
     * trailing wildcard (`172.17.*.*`), `host:` and `country:` entries, and
     * the path of a file listing more entries, one per line. Ranges in those
     * forms were IPv4 only. Files are only read for config entries, as the
     * old package did: a table row naming one is data, not a path to open.
     *
     * @param  array<string, true>  $files  files already being read, so one listing itself ends
     * @return array{list<string>, ?string}
     */
    private function expand(string $entry, bool $readFiles, array $files = []): array
    {
        if (str_starts_with($entry, 'country:')) {
            return [[], 'country entries need GeoIP, which watchtower leaves to the edge — see the Cloudflare block target'];
        }

        if (str_starts_with($entry, 'host:')) {
            return [[], 'a hostname resolves to an address that can change; add its current IP to the right list by hand'];
        }

        $target = IpRange::canonical($entry)
            ?? self::netmask($entry)
            ?? self::wildcard($entry);

        if ($target !== null) {
            return [[$target], null];
        }

        $range = self::dashRange($entry);

        if ($range !== null) {
            return [$range, null];
        }

        if ($readFiles && $entry !== '' && ! str_contains($entry, "\0") && is_file($entry) && ! isset($files[$entry])) {
            $targets = [];

            foreach (file($entry, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) ?: [] as $line) {
                [$found, $why] = $this->expand(trim($line), true, $files + [$entry => true]);

                if ($why !== null) {
                    $this->line("  skip   {$line} (in {$entry}) — {$why}");
                }

                array_push($targets, ...$found);
            }

            return [$targets, null];
        }

        return [[], 'not an address, range or readable file'];
    }

    /** `10.0.0.0/255.0.0.0` as `10.0.0.0/8`, if the mask is contiguous. */
    private static function netmask(string $entry): ?string
    {
        if (! preg_match('#^([\d.]+)/(\d+\.\d+\.\d+\.\d+)$#', $entry, $m) || ($mask = ip2long($m[2])) === false) {
            return null;
        }

        $host = ~$mask & 0xFFFFFFFF;

        return ($host & ($host + 1)) === 0
            ? IpRange::canonical($m[1].'/'.(32 - substr_count(decbin($host), '1')))
            : null;
    }

    /** `172.17.*.*` as `172.17.0.0/16`; only trailing octets may be wild. */
    private static function wildcard(string $entry): ?string
    {
        if (! preg_match('#^((?:\d{1,3}\.){0,3})\*(?:\.\*){0,3}$#', $entry, $m) || substr_count($entry, '.') !== 3) {
            return null;
        }

        $fixed = substr_count($m[1], '.');

        return IpRange::canonical($m[1].str_repeat('0.', 3 - $fixed).'0/'.(8 * $fixed));
    }

    /**
     * `10.0.0.1-10.0.0.255` as the fewest CIDR ranges that cover exactly it.
     *
     * @return list<string>|null
     */
    private static function dashRange(string $entry): ?array
    {
        [$from, $to] = array_pad(explode('-', $entry, 2), 2, '');
        $start = ip2long(trim($from));
        $end = ip2long(trim($to));

        if ($start === false || $end === false || $start > $end) {
            return null;
        }

        $ranges = [];

        while ($start <= $end) {
            // The largest block aligned at $start that doesn't pass $end.
            $size = $start === 0 ? 32 : strlen(decbin($start & -$start)) - 1;

            while ($start + (1 << $size) - 1 > $end) {
                $size--;
            }

            $ranges[] = (string) IpRange::canonical(long2ip($start).'/'.(32 - $size));
            $start += 1 << $size;
        }

        return $ranges;
    }

    /**
     * Print the whitelisted entries for never_block, minus what it already covers.
     *
     * @param  list<string>  $targets
     */
    private function allowlist(array $targets): void
    {
        $missing = array_values(array_filter($targets, fn ($target) => ! NeverBlockList::neverBlock((string) $target)));

        if ($missing === []) {
            return;
        }

        $current = array_values(array_filter(array_map('strval', (array) config('watchtower.never_block', []))));
        $all = array_merge($current, $missing);

        $this->newLine();
        $this->warn(count($missing).' whitelisted entr'.(count($missing) === 1 ? 'y is' : 'ies are').' not in never_block. Watchtower reads that list from config, so add them yourself — either in .env:');
        $this->line('WATCHTOWER_NEVER_BLOCK_IPS='.implode(',', $all));
        $this->line('or in config/watchtower.php:');
        $this->line("'never_block' => ['".implode("', '", $all)."'],");
        $this->newLine();
    }
}
