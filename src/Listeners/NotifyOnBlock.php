<?php

declare(strict_types=1);

namespace Watchtower\Listeners;

use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;
use Watchtower\Events\IpBlocked;

class NotifyOnBlock implements ShouldQueue
{
    public string $queue = 'default';

    public function handle(IpBlocked $event): void
    {
        $webhookUrl = config('watchtower.notifications.webhook_url');

        if (! $webhookUrl) {
            return;
        }

        try {
            Http::post($webhookUrl, [
                'ip'         => $event->record->ip,
                // null rather than the '' the column stores, so a receiver
                // can test the field rather than compare it. This array is
                // enumerated, so a new column never arrives here on its own.
                'scope'      => $event->record->scope ?: null,
                'reason'     => $event->record->reason,
                'source'     => $event->record->source->value,
                'source_env' => $event->record->source_env,
                'blocked_by' => $event->record->blocked_by,
                'expires_at' => $event->record->expires_at?->toIso8601String(),
                'blocked_at' => $event->record->created_at->toIso8601String(),
            ]);
        } catch (\Throwable $e) {
            Log::channel(config('watchtower.log_channel', 'stack'))->warning('Watchtower: webhook notification failed', [
                'ip'    => $event->record->ip,
                'error' => $e->getMessage(),
            ]);
        }
    }
}
