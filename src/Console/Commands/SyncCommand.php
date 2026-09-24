<?php

declare(strict_types=1);

namespace Watchtower\Console\Commands;

use Illuminate\Console\Command;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;
use Watchtower\Exceptions\NeverAutoBlockException;
use Watchtower\Exceptions\NeverBlockException;
use Watchtower\Services\BlacklistCache;
use Watchtower\Services\BlacklistService;
use Watchtower\Support\SyncSignature;

class SyncCommand extends Command
{
    protected $signature = 'watchtower:sync';

    protected $description = 'Pull the blacklist from the master environment and rebuild the local Redis cache';

    public function __construct(
        private readonly BlacklistCache $cache,
        private readonly BlacklistService $service,
    ) {
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
            $written = [];
            $skipped = 0;
            $whitelisted = 0;
            $autoRefused = 0;

            foreach ($blocks as $block) {
                try {
                    // The never-downgrade rule, never_block and the write all
                    // live in applySync(), shared with the push direction in
                    // SyncController — they were written out here as well,
                    // and the two copies had drifted (#38).
                    //
                    // deferCache because this run rebuilds once at the end
                    // rather than per record, and announce: false because a
                    // pulled block was already announced by the environment
                    // that received it. See the webhook contract in
                    // docs/configuration.md.
                    $result = $this->service->applySync($block['ip'], [
                        'reason'     => $block['reason'] ?? null,
                        'source_env' => $block['source_env'] ?? 'master',
                        'expires_at' => $block['expires_at'] ?? null,
                        'blocked_by' => $block['blocked_by'] ?? null,
                        // The master's own row carries its source, so the
                        // pull direction has always had this on the wire —
                        // only the push payload needed a new field. A master
                        // row that is itself `sync` came from a third node
                        // and no longer knows what decided it, which reads
                        // here as unknown, the same as a master too old to
                        // send it (#56).
                        'origin_source' => $block['source'] ?? null,
                    ], deferCache: true, announce: false);
                } catch (NeverAutoBlockException) {
                    // Refused because a RULE elsewhere decided it and this
                    // node's never_auto_block covers the address. Counted
                    // apart from never_block: an admin here could still
                    // block it, so the two are not the same answer.
                    $autoRefused++;

                    continue;
                } catch (NeverBlockException) {
                    // The master can block an address this environment has
                    // whitelisted; it does not get to write it here.
                    $whitelisted++;

                    continue;
                }

                if (! $result['applied']) {
                    $skipped++;

                    continue;
                }

                $written[] = $result['record'];
            }

            $synced = count($written);
            $refused = $whitelisted === 0 ? '' : "; {$whitelisted} refused by never_block";
            $refused .= $autoRefused === 0 ? '' : "; {$autoRefused} refused by never_auto_block";

            // rebuild() logs and swallows its own DB failure, so ask it. The
            // middleware reads only the cache, so write what was just synced
            // directly, as BlacklistService::block() does. Still fail the run:
            // the DB read is failing, and cron is how anyone finds out.
            if (! $this->cache->rebuild()) {
                foreach ($written as $record) {
                    $this->cache->put($record);
                }

                $this->error("Synced {$synced} IPs from master ({$skipped} skipped{$refused}) and wrote them to the cache directly, but the cache rebuild failed — its DB read error is on the watchtower log channel.");

                return self::FAILURE;
            }

            // "live" is the guarantee, not decoration: a lapsed local row used
            // to be counted here too, while preserving nothing (#74).
            $this->info("Synced {$synced} IPs from master ({$skipped} skipped — live local manual/auto blocks preserved{$refused}). Redis cache rebuilt.");

            return self::SUCCESS;

        } catch (\Throwable $e) {
            $this->error('Sync error: '.$e->getMessage());
            Log::channel(config('watchtower.log_channel', 'stack'))->error('Watchtower: sync exception', ['error' => $e->getMessage()]);

            return self::FAILURE;
        }
    }
}
