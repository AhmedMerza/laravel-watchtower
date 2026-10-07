<?php

declare(strict_types=1);

namespace Watchtower\Console\Commands;

use Illuminate\Console\Command;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Notification;
use Watchtower\Notifications\BlockDigest;
use Watchtower\Support\AlertChannels;
use Watchtower\Support\BlockScope;

class AlertDigestCommand extends Command
{
    protected $signature = 'watchtower:alert-digest';

    protected $description = 'Send every block and near miss since the last digest as one message';

    /** Addresses listed in one digest; the rest are counted, not listed. */
    public const MAX_ENTRIES = 50;

    public function handle(): int
    {
        $config = config('watchtower.notifications.alerts', []);

        if (! ($config['enabled'] ?? false) || ! ($config['digest']['enabled'] ?? false)) {
            $this->info('The alert digest is off (notifications.alerts.digest.enabled).');

            return self::SUCCESS;
        }

        $routes = AlertChannels::routes($config['routes'] ?? []);

        if ($routes === []) {
            $this->warn('No alert route has a value (notifications.alerts.routes), so there is nowhere to send the digest.');

            return self::SUCCESS;
        }

        // Everything up to here and no further. Rows a block writes while
        // this sends have a higher id, so the delete below leaves them for
        // tomorrow's digest instead of dropping them unreported.
        $last = DB::table('watchtower_alert_digest')->max('id');

        if ($last === null) {
            $this->info('Nothing to report since the last digest.');

            return self::SUCCESS;
        }

        $digest = $this->digest((int) $last, (bool) ($config['digest']['instant'] ?? true));
        $class = $config['digest']['notification'] ?? BlockDigest::class;

        // One channel at a time, as the instant alert does: a broken Slack
        // webhook must not cost the mail.
        $delivered = false;

        foreach ($routes as $channel => $route) {
            try {
                Notification::route($channel, $route)->notify(new $class($digest));
                $delivered = true;
            } catch (\Throwable $e) {
                $this->warn("Could not send the digest on {$channel}: {$e->getMessage()}");
                Log::channel(config('watchtower.log_channel', 'stack'))->warning('Watchtower: alert digest failed', [
                    'channel' => $channel,
                    'error'   => $e->getMessage(),
                ]);
            }
        }

        // Kept when nothing went out, so the next run reports them. Once one
        // channel has delivered, they are gone: keeping them for a channel
        // that is broken for good would repeat the day on the others forever.
        if (! $delivered) {
            $this->error('The digest went out on no channel; its entries are kept for the next run.');

            return self::FAILURE;
        }

        $sent = DB::table('watchtower_alert_digest')->where('id', '<=', $last)->delete();

        $addresses = array_sum($digest['totals']);
        $this->info("Sent the digest: {$sent} event(s) across {$addresses} address(es).");

        return self::SUCCESS;
    }

    /**
     * Grouped in the database, so a busy day costs one row per address here,
     * not one per event. `sent` is grouped on rather than summed: summing a
     * boolean is written differently on every driver.
     *
     * @return array<string, mixed>
     */
    private function digest(int $last, bool $instant): array
    {
        $rows = DB::table('watchtower_alert_digest')
            ->where('id', '<=', $last)
            ->select(['type', 'ip', 'scope', 'reason', 'not_blocked_because', 'sent'])
            ->selectRaw('count(*) as events, min(created_at) as first_at, max(created_at) as last_at')
            ->groupBy(['type', 'ip', 'scope', 'reason', 'not_blocked_because', 'sent'])
            ->get();

        $entries = [];

        foreach ($rows as $row) {
            $key = implode("\0", [$row->type, $row->ip, $row->scope, $row->reason, $row->not_blocked_because]);
            $entry = $entries[$key] ?? [
                'type'                => $row->type,
                'ip'                  => $row->ip,
                'scope'               => $row->scope === BlockScope::GLOBAL ? null : $row->scope,
                'reason'              => $row->reason,
                'not_blocked_because' => $row->not_blocked_because,
                'events'              => 0,
                'held_back'           => 0,
                'first_at'            => (string) $row->first_at,
                'last_at'             => (string) $row->last_at,
            ];

            $entry['events'] += (int) $row->events;
            $entry['held_back'] += $row->sent ? 0 : (int) $row->events;
            $entry['first_at'] = min($entry['first_at'], (string) $row->first_at);
            $entry['last_at'] = max($entry['last_at'], (string) $row->last_at);
            $entries[$key] = $entry;
        }

        // Blocks first, then the busiest.
        usort($entries, fn (array $a, array $b) => [$a['type'] !== 'blocked', $b['events']] <=> [$b['type'] !== 'blocked', $a['events']]);

        $totals = ['blocked' => [], 'would_have_blocked' => []];

        foreach ($entries as $entry) {
            $totals[$entry['type']][$entry['ip']."\0".$entry['scope']] = true;
        }

        return [
            'since'   => min(array_column($entries, 'first_at')),
            'instant' => $instant,
            'totals'  => array_map('count', $totals),
            'entries' => array_slice($entries, 0, self::MAX_ENTRIES),
            'omitted' => max(0, count($entries) - self::MAX_ENTRIES),
            'url'     => AlertChannels::link(),
        ];
    }
}
