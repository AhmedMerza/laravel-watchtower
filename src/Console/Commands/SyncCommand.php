<?php

declare(strict_types=1);

namespace Watchtower\Console\Commands;

use Illuminate\Console\Command;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;
use Watchtower\Enums\BlockSource;
use Watchtower\Models\BlacklistedIp;
use Watchtower\Services\BlacklistCache;
use Watchtower\Support\SyncSignature;

class SyncCommand extends Command
{
    protected $signature = 'watchtower:sync';

    protected $description = 'Pull the blacklist from the master environment and rebuild the local Redis cache';

    public function __construct(private readonly BlacklistCache $cache)
    {
        parent::__construct();
    }

    public function handle(): int
    {
        $masterUrl = config('watchtower.sync.master_url');
        $secret = SyncSignature::secret();

        if (! $masterUrl) {
            $this->error('WATCHTOWER_MASTER_URL is not configured. Set it in your .env file.');

            return self::FAILURE;
        }

        if ($secret === '') {
            $this->error('WATCHTOWER_SYNC_SECRET is not configured. The master rejects unsigned requests — set the same secret on every environment.');

            return self::FAILURE;
        }

        try {
            $response = Http::withHeaders(
                SyncSignature::headers('GET', SyncSignature::PULL_PATH, '', $secret)
                + ['Accept' => 'application/json']
            )->get(rtrim((string) $masterUrl, '/').SyncSignature::PULL_PATH);

            if (! $response->successful()) {
                $this->error("Sync failed — master returned HTTP {$response->status()}.");
                Log::channel(config('watchtower.log_channel', 'stack'))->error('Watchtower: sync failed', ['status' => $response->status()]);

                return self::FAILURE;
            }

            $blocks = $response->json('data', []);
            $synced = 0;
            $skipped = 0;

            foreach ($blocks as $block) {
                // Never downgrade a manual or auto block with a sync record —
                // only insert if the IP isn't already locally blocked.
                $existing = BlacklistedIp::where('ip', $block['ip'])->first();

                if ($existing && $existing->source !== BlockSource::Sync) {
                    $skipped++;

                    continue;
                }

                BlacklistedIp::updateOrCreate(
                    ['ip' => $block['ip']],
                    [
                        'reason'       => $block['reason'] ?? null,
                        'source_env'   => $block['source_env'] ?? 'master',
                        'source'       => BlockSource::Sync,
                        'expires_at'   => $block['expires_at'] ?? null,
                        'blocked_by'   => $block['blocked_by'] ?? null,
                        'log_entry_id' => $block['log_entry_id'] ?? null,
                    ]
                );
                $synced++;
            }

            // rebuild() logs and swallows its own DB failure, so ask it. Saying
            // "cache rebuilt" and exiting 0 here hands cron a green run while
            // the cached blocklist is stale — missing IPs master says to block.
            if (! $this->cache->rebuild()) {
                $this->error("Synced {$synced} IPs from master ({$skipped} skipped), but the cache rebuild failed — the blocklist in cache is stale.");

                return self::FAILURE;
            }

            $this->info("Synced {$synced} IPs from master ({$skipped} skipped — local manual/auto blocks preserved). Redis cache rebuilt.");

            return self::SUCCESS;

        } catch (\Throwable $e) {
            $this->error('Sync error: '.$e->getMessage());
            Log::channel(config('watchtower.log_channel', 'stack'))->error('Watchtower: sync exception', ['error' => $e->getMessage()]);

            return self::FAILURE;
        }
    }
}
