<?php

declare(strict_types=1);

namespace Watchtower\Listeners;

use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Notification;
use Illuminate\Support\Facades\Route;
use Watchtower\Enums\BlockSource;
use Watchtower\Events\IpBlocked;
use Watchtower\Events\WouldHaveBlocked;
use Watchtower\Notifications\BlockAlert;
use Watchtower\Support\BlockScope;

/**
 * Mail/Slack/any-channel alerts on a block or a near miss (#124).
 *
 * Not queued itself: the throttle check is one cache write, and doing it here
 * keeps a scanner rotating through a hundred tries from queueing a hundred
 * jobs only to drop ninety-nine. The notification it sends is queued.
 */
class SendBlockAlert
{
    public function handle(IpBlocked|WouldHaveBlocked $event): void
    {
        $config = config('watchtower.notifications.alerts', []);

        if (! ($config['enabled'] ?? false)) {
            return;
        }

        $alert = $event instanceof IpBlocked
            ? $this->blocked($event, $config)
            : $this->wouldHaveBlocked($event, $config);

        if ($alert === null) {
            return;
        }

        $routes = $this->routes($config['routes'] ?? []);

        if ($routes === [] || ! $this->firstInWindow($alert, (int) ($config['throttle_minutes'] ?? 60))) {
            return;
        }

        $class = $config['notification'] ?? BlockAlert::class;

        // Caught, not thrown: this runs inside the block itself, and on the
        // sync queue driver inside the send too. A mail server that is down
        // must not undo or crash the block it was only meant to report.
        try {
            $notifiable = Notification::routes($routes);
            $notifiable->notify(new $class($alert));
        } catch (\Throwable $e) {
            Log::channel(config('watchtower.log_channel', 'stack'))->warning('Watchtower: block alert failed', [
                'ip'    => $alert['ip'],
                'error' => $e->getMessage(),
            ]);
        }
    }

    /**
     * Auto-blocks always; manual ones when asked. Sync never — the install the
     * block came from already alerted — and neither do feed imports, which
     * write thousands of known-bad addresses nobody needs to hear about.
     *
     * @param  array<string, mixed>  $config
     * @return array<string, mixed>|null
     */
    private function blocked(IpBlocked $event, array $config): ?array
    {
        $record = $event->record;

        $wanted = $record->source === BlockSource::Auto
            || ($record->source === BlockSource::Manual && ($config['manual'] ?? false));

        if (! $wanted) {
            return null;
        }

        return [
            'type'       => 'blocked',
            'ip'         => $record->ip,
            'reason'     => (string) $record->reason,
            'scope'      => $record->scope === BlockScope::GLOBAL ? null : $record->scope,
            'source'     => $record->source->value,
            'expires_at' => $record->expires_at?->toIso8601String(),
            'url'        => $this->url(),
        ];
    }

    /**
     * @param  array<string, mixed>  $config
     * @return array<string, mixed>|null
     */
    private function wouldHaveBlocked(WouldHaveBlocked $event, array $config): ?array
    {
        if (! ($config['would_have_blocked'] ?? false)) {
            return null;
        }

        return [
            'type'                => 'would_have_blocked',
            'ip'                  => $event->ip,
            'reason'              => $event->reason,
            'scope'               => $event->scope === BlockScope::GLOBAL ? null : $event->scope,
            'not_blocked_because' => $event->notBlockedBecause,
            // The rule's own config array stays out: it rides into a queued
            // job, and an app's rule may hold something that can't serialize.
            'context'             => array_diff_key($event->context, ['rule' => true]),
            'url'                 => $this->url(),
        ];
    }

    /**
     * Channel => route, keeping only the ones given a value, so an unset env
     * var turns its channel off. A comma-separated mail route becomes a list.
     *
     * @param  array<string, mixed>  $routes
     * @return array<string, mixed>
     */
    private function routes(array $routes): array
    {
        $routes = array_filter($routes, fn ($route) => $route !== null && $route !== '' && $route !== []);

        if (is_string($routes['mail'] ?? null)) {
            $routes['mail'] = array_values(array_filter(array_map('trim', explode(',', $routes['mail']))));
        }

        return $routes;
    }

    /**
     * One alert per address per kind per window. Per kind, so a near miss in
     * the morning can't swallow the alert for the real block that follows.
     *
     * @param  array<string, mixed>  $alert
     */
    private function firstInWindow(array $alert, int $minutes): bool
    {
        if ($minutes <= 0) {
            return true;
        }

        $store = config('watchtower.cache.store');
        $prefix = (string) config('watchtower.cache.key', 'watchtower:blacklist');

        return Cache::store(is_string($store) ? $store : null)
            ->add("{$prefix}:alert:{$alert['type']}:{$alert['ip']}", true, $minutes * 60);
    }

    /**
     * Resolved here, at the block, not in the queued job: the worker has no
     * request, and the management page is only routed when the UI is on.
     */
    private function url(): ?string
    {
        return Route::has('watchtower.ui.index') ? route('watchtower.ui.index') : null;
    }
}
