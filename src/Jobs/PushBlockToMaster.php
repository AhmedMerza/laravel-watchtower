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
use Watchtower\Enums\BlockSource;
use Watchtower\Models\BlacklistedIp;
use Watchtower\Support\SyncSignature;

class PushBlockToMaster implements ShouldQueue
{
    use Dispatchable, InteractsWithQueue, Queueable, SerializesModels;

    public int $tries = 3;

    public int $backoff = 30;

    public function __construct(public readonly BlacklistedIp $record) {}

    public function handle(): void
    {
        $masterUrl = config('watchtower.sync.master_url');
        $secret = (string) config('watchtower.sync.secret', '');

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

        $payload = [
            'ip'         => $this->record->ip,
            'reason'     => $this->record->reason,
            'source_env' => app()->environment(),
            'expires_at' => $this->record->expires_at?->toIso8601String(),
            'blocked_by' => $this->record->blocked_by,
        ];

        // Sign and send the same bytes. Handing the array to post() would let
        // the HTTP client re-encode it, and any difference invalidates the
        // signature on arrival.
        $body = json_encode($payload, JSON_THROW_ON_ERROR);

        $response = Http::withHeaders(
            SyncSignature::headers('POST', SyncSignature::PUSH_PATH, $body, $secret)
        )
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
