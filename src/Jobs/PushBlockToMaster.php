<?php

declare(strict_types=1);

namespace Watchtower\Jobs;

use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Foundation\Bus\Dispatchable;
use Illuminate\Queue\InteractsWithQueue;
use Illuminate\Queue\SerializesModels;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Str;
use Watchtower\Enums\BlockSource;
use Watchtower\Models\BlacklistedIp;
use Watchtower\Support\SyncSignature;

class PushBlockToMaster implements ShouldQueue
{
    use Dispatchable, InteractsWithQueue, Queueable, SerializesModels;

    /** Matches the max on SyncController's reason rule. */
    private const REASON_LIMIT = 500;

    public int $tries = 3;

    public int $backoff = 30;

    public function __construct(public readonly BlacklistedIp $record) {}

    public function handle(): void
    {
        $masterUrl = config('watchtower.sync.master_url');
        $secret = SyncSignature::secret();

        if (! $masterUrl) {
            return;
        }

        // A block that arrived by sync is not ours to report. Without this a
        // master whose own master_url points at itself pushes every incoming
        // block straight back to itself, forever.
        if ($this->record->source === BlockSource::Sync) {
            return;
        }

        if ($secret === '') {
            Log::channel(config('watchtower.log_channel', 'stack'))->warning(
                'Watchtower: WATCHTOWER_MASTER_URL is set but WATCHTOWER_SYNC_SECRET is not, so the block cannot be signed and was not pushed.',
                ['ip' => $this->record->ip]
            );

            return;
        }

        // reason is a text column here but the master validates it at 500, so
        // send what the master will accept. An auto-block rule with a verbose
        // template would otherwise fail validation on arrival, and a block
        // that never propagates is worse than one with a clipped reason.
        $payload = [
            'ip'         => $this->record->ip,
            'reason'     => $this->record->reason === null
                ? null
                // -3 because Str::limit appends its ellipsis AFTER truncating,
                // so limit(…, 500) returns 503 and fails the master's rule.
                : Str::limit($this->record->reason, self::REASON_LIMIT - 3),
            'source_env' => app()->environment(),
            // What decided this block HERE, so the master can apply its own
            // never_auto_block to a rule's decision without also refusing an
            // admin's. A Sync record is never pushed onward, so this is only
            // ever 'manual' or 'auto'. A master too old to know the field
            // ignores it (#56).
            'source'     => $this->record->source->value,
            'expires_at' => $this->record->expires_at?->toIso8601String(),
            'blocked_by' => $this->record->blocked_by,
        ];

        // Sign and send the same bytes. Handing the array to post() would let
        // the HTTP client re-encode it, and any difference invalidates the
        // signature on arrival.
        $body = json_encode($payload, JSON_THROW_ON_ERROR);

        // Accept matters more than it looks. Without it Laravel renders a
        // validation failure on the master as a 302 to its own home page
        // rather than a 422 — and a followed redirect returning 2xx would
        // mark this job successful with the block never recorded.
        // withoutRedirecting() is the belt to that braces.
        $response = Http::withHeaders(
            SyncSignature::headers('POST', SyncSignature::PUSH_PATH, $body, $secret)
            + ['Accept' => 'application/json']
        )
            ->withoutRedirecting()
            ->withBody($body, 'application/json')
            ->post(rtrim((string) $masterUrl, '/').SyncSignature::PUSH_PATH);

        if (! $response->successful()) {
            throw new \RuntimeException("Master returned HTTP {$response->status()} for IP {$this->record->ip}");
        }
    }

    public function failed(\Throwable $e): void
    {
        Log::channel(config('watchtower.log_channel', 'stack'))->warning('Watchtower: PushBlockToMaster failed', [
            'ip'    => $this->record->ip,
            'error' => $e->getMessage(),
        ]);
    }
}
