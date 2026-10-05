<?php

declare(strict_types=1);

namespace Watchtower\Console\Commands;

use Illuminate\Console\Command;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;
use Watchtower\Enums\SyncRole;
use Watchtower\Exceptions\NeverAutoBlockException;
use Watchtower\Exceptions\NeverBlockException;
use Watchtower\Models\BlacklistedIp;
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

        // The role first: a bad one is the real problem even when the URL
        // is missing too.
        if (($invalid = SyncRole::invalid()) !== null) {
            $this->error("WATCHTOWER_SYNC_ROLE is '{$invalid}'; it must be master or satellite, or unset.");

            return self::FAILURE;
        }

        if (SyncRole::current() === SyncRole::Master) {
            $this->error('This environment is the master (WATCHTOWER_SYNC_ROLE=master), and watchtower:sync pulls from the master. Schedule it on the satellites only.');

            return self::FAILURE;
        }

        if (! $masterUrl) {
            $this->error('WATCHTOWER_MASTER_URL is not configured. Set it in your .env file.');

            return self::FAILURE;
        }

        if ($secret === '') {
            $this->error('WATCHTOWER_SYNC_SECRET is not configured. The master rejects unsigned requests — set the same secret on every environment.');

            return self::FAILURE;
        }

        $written = [];
        $skipped = 0;
        $whitelisted = 0;
        $autoRefused = 0;

        try {
            // Page until the master says there is no more (#37). A master
            // older than paging ignores `after` and sends no next_cursor, so
            // against one this is a single request for the whole list. The
            // cursor is a ULID; '0' sorts before every one of them.
            $cursor = '0';

            do {
                $response = Http::withHeaders(
                    SyncSignature::headers('GET', SyncSignature::PULL_PATH, '', $secret)
                    + ['Accept' => 'application/json']
                )->get(rtrim((string) $masterUrl, '/').SyncSignature::PULL_PATH, ['after' => $cursor]);

                if (! $response->successful()) {
                    $this->error("Sync failed — master returned HTTP {$response->status()}.".SyncRole::hintFor($response->status()));
                    Log::channel(config('watchtower.log_channel', 'stack'))->error('Watchtower: sync failed', ['status' => $response->status()]);

                    return $this->abandon($written);
                }

                $blocks = $response->json('data', []);
                $next = $response->json('next_cursor');

                // A cursor that doesn't move forward would loop forever.
                // strcmp, not <=: PHP compares numeric-looking strings as
                // numbers.
                if ($next !== null && (! is_string($next) || strcmp($next, $cursor) <= 0)) {
                    $this->error("Sync failed — master returned an invalid next_cursor after {$cursor}.");

                    return $this->abandon($written);
                }

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

                $cursor = $next;
            } while ($cursor !== null);

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

            return $this->abandon($written);
        }
    }

    /**
     * Fail a run part-way through the pages. The pages already applied
     * deferred their cache writes to a rebuild this run will no longer reach,
     * and the middleware reads only the cache — so do the rebuild here, or
     * those rows sit in the database unenforced until the next good run.
     *
     * @param  list<BlacklistedIp>  $written
     */
    private function abandon(array $written): int
    {
        if ($written !== [] && ! $this->cache->rebuild()) {
            foreach ($written as $record) {
                $this->cache->put($record);
            }
        }

        return self::FAILURE;
    }
}
