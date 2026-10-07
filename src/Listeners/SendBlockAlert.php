<?php

declare(strict_types=1);

namespace Watchtower\Listeners;

use Illuminate\Contracts\Cache\Repository;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Notification;
use Watchtower\Enums\BlockSource;
use Watchtower\Events\IpBlocked;
use Watchtower\Events\WouldHaveBlocked;
use Watchtower\Notifications\BlockAlert;
use Watchtower\Services\BlacklistService;
use Watchtower\Support\AlertChannels;
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

        $routes = AlertChannels::routes($config['routes'] ?? []);

        if ($routes === []) {
            return;
        }

        $digest = (bool) ($config['digest']['enabled'] ?? false);
        $sent = (! $digest || ($config['digest']['instant'] ?? true)) && $this->alertNow($alert, $routes, $config);

        // Every event, sent or not: the digest is the whole day, and what the
        // throttle or cap held back is exactly what it exists to report.
        // Nothing is recorded with no route to send it on: the digest
        // couldn't go anywhere either.
        if ($digest) {
            $this->record($alert, $sent);
        }
    }

    /**
     * The instant alert, through the throttle and cap. True when at least one
     * channel took it.
     *
     * @param  array<string, mixed>  $alert
     * @param  array<string, mixed>  $routes
     * @param  array<string, mixed>  $config
     */
    private function alertNow(array $alert, array $routes, array $config): bool
    {
        $minutes = (int) ($config['throttle_minutes'] ?? 60);

        // What this alert has taken so far, filled in step by step, so a
        // failure at any point hands back exactly that and nothing more.
        $taken = ['slot' => null, 'counter' => null];

        // Everything from the first cache call on is caught, not thrown: this
        // runs inside the block itself, and on the sync queue driver inside
        // the send too. A cache or mail server that is down must not undo or
        // crash the block it was only meant to report — nor the request a
        // detector is checking.
        try {
            if (! $this->claim($alert, $minutes, (int) ($config['max_per_window'] ?? 20), $taken)) {
                return false;
            }

            $alert['url'] = AlertChannels::link();
            $class = $config['notification'] ?? BlockAlert::class;
            $notifications = array_map(fn () => new $class($alert), $routes);
        } catch (\Throwable $e) {
            $this->handBack($taken);
            $this->logFailure($alert, $e);

            return false;
        }

        // One channel at a time. Laravel sends an on-demand notification's
        // channels in turn and stops at the first that throws, so on the sync
        // driver a broken Slack webhook would cost the mail behind it.
        $delivered = false;

        foreach ($routes as $channel => $route) {
            try {
                Notification::route($channel, $route)->notify($notifications[$channel]);
                $delivered = true;
            } catch (\Throwable $e) {
                $this->logFailure($alert, $e, $channel);
            }
        }

        // Handed back only when nothing went out. A mailer down for a minute
        // must not silence the address — or use up the cap — for the window;
        // but once one channel has delivered, keeping the slot is what stops
        // a permanently broken second channel from re-sending the first on
        // every event.
        if (! $delivered) {
            $this->handBack($taken);
        }

        return $delivered;
    }

    /**
     * Count the event into its address's open digest row, or start one.
     * Caught like everything else here: a missing table — the migration not
     * yet run — must not cost the block.
     *
     * By id, not by the matching columns: two events racing to start the
     * same row can leave two, and an update by columns would then count
     * every later repeat twice. Two rows the digest adds up; double counts it
     * can't undo. An update that finds the row sealed by a digest mid-send
     * changes nothing, and the event starts the next row.
     *
     * @param  array<string, mixed>  $alert
     */
    private function record(array $alert, bool $sent): void
    {
        try {
            $row = [
                'type'                => $alert['type'],
                'ip'                  => app(BlacklistService::class)->normalizeTarget($alert['ip']),
                'scope'               => $alert['scope'] ?? BlockScope::GLOBAL,
                'reason'              => $alert['reason'],
                'not_blocked_because' => $alert['not_blocked_because'] ?? null,
            ];

            $open = fn () => DB::table('watchtower_alert_digest')->where('sealed', false);

            $id = $open()
                ->where('ip', $row['ip'])
                ->where('type', $row['type'])
                ->where('scope', $row['scope'])
                ->where('reason', $row['reason'])
                ->where(fn ($q) => $row['not_blocked_because'] === null
                    ? $q->whereNull('not_blocked_because')
                    : $q->where('not_blocked_because', $row['not_blocked_because']))
                ->value('id');

            $counted = $id !== null && $open()->where('id', $id)->incrementEach(
                ['events' => 1, 'held_back' => $sent ? 0 : 1],
                ['last_at' => now()],
            ) > 0;

            if (! $counted) {
                DB::table('watchtower_alert_digest')->insert([
                    ...$row,
                    'events'    => 1,
                    'held_back' => $sent ? 0 : 1,
                    'sealed'    => false,
                    'first_at'  => now(),
                    'last_at'   => now(),
                ]);
            }
        } catch (\Throwable $e) {
            Log::channel(config('watchtower.log_channel', 'stack'))->warning('Watchtower: could not record the alert for the digest', [
                'ip'    => $alert['ip'],
                'error' => $e->getMessage(),
            ]);
        }
    }

    /**
     * @param  array{slot: ?string, counter: ?string}  $taken
     */
    private function handBack(array $taken): void
    {
        if ($taken['slot'] !== null) {
            rescue(fn () => $this->cache()->forget($taken['slot']), report: false);
        }

        if ($taken['counter'] !== null) {
            rescue(fn () => $this->cache()->decrement($taken['counter']), report: false);
        }
    }

    /**
     * @param  array<string, mixed>  $alert
     */
    private function logFailure(array $alert, \Throwable $e, ?string $channel = null): void
    {
        Log::channel(config('watchtower.log_channel', 'stack'))->warning('Watchtower: block alert failed', array_filter([
            'ip'      => $alert['ip'],
            'channel' => $channel,
            'error'   => $e->getMessage(),
        ], fn ($value) => $value !== null));
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
     * The cap counts in fixed windows named by their start, not a key whose
     * TTL is set once by add(): a key that expires between add() and
     * increment() is recreated by increment() with no TTL on some stores, and
     * a forever counter would mute the kind for good. Named by window, a key
     * that loses its TTL belongs to a window already over.
     *
     * @param  array<string, mixed>  $alert
     * @param  array{slot: ?string, counter: ?string}  $taken
     */
    private function claim(array $alert, int $minutes, int $max, array &$taken): bool
    {
        if ($minutes <= 0) {
            return true;
        }

        $seconds = $minutes * 60;
        $prefix = (string) config('watchtower.cache.key', 'watchtower:blacklist');
        $target = app(BlacklistService::class)->normalizeTarget($alert['ip']);
        $slot = "{$prefix}:alert:{$alert['type']}:".($alert['scope'] ?? '').":{$target}";

        if (! $this->cache()->add($slot, true, $seconds)) {
            return false;
        }

        $taken['slot'] = $slot;

        if ($max <= 0) {
            return true;
        }

        $window = intdiv(now()->getTimestamp(), $seconds);
        $counter = "{$prefix}:alert:{$alert['type']}:count:{$window}";

        $this->cache()->add($counter, 0, $seconds * 2);
        $sent = (int) $this->cache()->increment($counter);
        $taken['counter'] = $counter;

        if ($sent <= $max) {
            return true;
        }

        if ($sent === $max + 1) {
            Log::channel(config('watchtower.log_channel', 'stack'))->warning('Watchtower: alert cap reached, further alerts suppressed', [
                'type'           => $alert['type'],
                'max_per_window' => $max,
                'window_minutes' => $minutes,
            ]);
        }

        // Nothing was sent for this address, so it keeps no slot: once the
        // cap's window turns over, its next block reports like any other.
        $this->cache()->forget($slot);

        return false;
    }

    private function cache(): Repository
    {
        $store = config('watchtower.cache.store');

        return Cache::store(is_string($store) ? $store : null);
    }
}
