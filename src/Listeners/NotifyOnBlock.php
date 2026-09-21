<?php

declare(strict_types=1);

namespace Watchtower\Listeners;

use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;
use Watchtower\Events\IpBlocked;
use Watchtower\Support\BlockScope;

class NotifyOnBlock implements ShouldQueue
{
    /**
     * A method rather than the `$queue` property Laravel also accepts: a
     * property initialiser can't call config(), so the property could only
     * ever hold the literal 'default' — which is what made
     * WATCHTOWER_NOTIFICATION_QUEUE do nothing for the webhook it names.
     * The dispatcher reads this at dispatch time, when config is loaded.
     */
    public function viaQueue(): string
    {
        return config('watchtower.notifications.queue', 'default');
    }

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
                //
                // Strict comparison, not `?:`: a scope named '0' is falsy but
                // is a perfectly valid declared name, and would otherwise be
                // reported to receivers as an app-wide block.
                'scope'      => $event->record->scope === BlockScope::GLOBAL ? null : $event->record->scope,
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
