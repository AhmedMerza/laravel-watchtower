<?php

declare(strict_types=1);

namespace Watchtower\Listeners;

use Illuminate\Contracts\Cache\Repository;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Notification;
use Illuminate\Support\Facades\Route;
use Watchtower\Enums\BlockSource;
use Watchtower\Events\IpBlocked;
use Watchtower\Events\WouldHaveBlocked;
use Watchtower\Notifications\BlockAlert;
use Watchtower\Services\BlacklistService;
use Watchtower\Support\BlockScope;

/**
 * Mail/Slack/any-channel alerts on a block or a near miss (#124).
 *
 * Not queued itself: the throttle check is a couple of cache writes, and
 * doing it here keeps a scanner rotating through a hundred addresses from
 * queueing a hundred jobs only to drop most of them. The notification it
 * sends is queued.
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

        if ($routes === []) {
            return;
        }

        $minutes = (int) ($config['throttle_minutes'] ?? 60);
        $slot = null;

        // Everything from the first cache call on is caught, not thrown: this
        // runs inside the block itself, and on the sync queue driver inside
        // the send too. A cache or mail server that is down must not undo or
        // crash the block it was only meant to report — nor the request a
        // detector is checking.
        try {
            $slot = $this->claimSlot($alert, $minutes, (int) ($config['max_per_window'] ?? 20));

            if ($slot === false) {
                return;
            }

            $alert['url'] = $this->url();
            $class = $config['notification'] ?? BlockAlert::class;

            Notification::routes($routes)->notify(new $class($alert));
        } catch (\Throwable $e) {
            // Give the slot back, or a mailer that was down for a minute
            // would silence this address for the rest of the window.
            if (is_string($slot)) {
                rescue(fn () => $this->cache()->forget($slot), report: false);
            }

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
     * Two limits, both per kind (blocked, would have blocked) so a near miss
     * can't swallow the alert for the real block that follows:
     *
     * - one alert per address and scope per window. The address is the block
     *   target, so an IPv6 near miss counts against its /64 the way the block
     *   would — and a scope escalating to the whole app still reports.
     * - at most $max alerts of the kind per window across all addresses, so a
     *   scanner rotating through a thousand addresses sends $max, not a
     *   thousand. The first one over the cap is logged, once.
     *
     * Returns the per-address key it claimed (handed back if the send fails),
     * null when throttling is off, or false when this alert is suppressed.
     *
     * @param  array<string, mixed>  $alert
     */
    private function claimSlot(array $alert, int $minutes, int $max): string|false|null
    {
        if ($minutes <= 0) {
            return null;
        }

        $prefix = (string) config('watchtower.cache.key', 'watchtower:blacklist');
        $target = app(BlacklistService::class)->normalizeTarget($alert['ip']);
        $slot = "{$prefix}:alert:{$alert['type']}:".($alert['scope'] ?? '').":{$target}";

        if (! $this->cache()->add($slot, true, $minutes * 60)) {
            return false;
        }

        if ($max <= 0) {
            return $slot;
        }

        $counter = "{$prefix}:alert:{$alert['type']}:count";
        $this->cache()->add($counter, 0, $minutes * 60);
        $sent = (int) $this->cache()->increment($counter);

        if ($sent === $max + 1) {
            Log::channel(config('watchtower.log_channel', 'stack'))->warning('Watchtower: alert cap reached, further alerts suppressed', [
                'type'           => $alert['type'],
                'max_per_window' => $max,
                'window_minutes' => $minutes,
            ]);
        }

        return $sent > $max ? false : $slot;
    }

    private function cache(): Repository
    {
        $store = config('watchtower.cache.store');

        return Cache::store(is_string($store) ? $store : null);
    }

    /**
     * Resolved here, at the block, not in the queued job, because the
     * management page is only routed when the UI is on.
     *
     * Rooted at APP_URL, never at the current request. A real-time detector
     * blocks inside the very request it caught, and route() would take that
     * request's Host header — the attacker's — and put their link in the
     * operator's security alert. A UI route with its own domain is built from
     * that domain, which no request can change.
     */
    private function url(): ?string
    {
        $route = Route::getRoutes()->getByName('watchtower.ui.index');

        if ($route === null) {
            return null;
        }

        return $route->getDomain() !== null
            ? route('watchtower.ui.index')
            : rtrim((string) config('app.url'), '/').route('watchtower.ui.index', [], false);
    }
}
