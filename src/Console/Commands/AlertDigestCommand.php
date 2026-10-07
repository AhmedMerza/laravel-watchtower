<?php

declare(strict_types=1);

namespace Watchtower\Console\Commands;

use Illuminate\Console\Command;
use Illuminate\Database\Query\Builder;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Notification;
use Illuminate\Support\Facades\Schema;
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

        if (! Schema::hasTable('watchtower_alert_digest')) {
            $this->error('The watchtower_alert_digest table is missing. Publish and run the migration: php artisan vendor:publish --tag=watchtower-migrations && php artisan migrate');

            return self::FAILURE;
        }

        // Claim what is there now. A block during the send counts into a new,
        // unsealed row, which the delete below leaves for the next digest.
        // Rows a failed run sealed stay sealed and go out with the next one.
        //
        // Bounded by the highest id at the seal, so a second run started by
        // hand alongside the scheduled one can't have its rows deleted by
        // this one: every row it seals is newer than this ceiling.
        DB::table('watchtower_alert_digest')->where('sealed', false)->update(['sealed' => true]);
        $ceiling = DB::table('watchtower_alert_digest')->where('sealed', true)->max('id');

        if ($ceiling === null) {
            $this->info('Nothing to report since the last digest.');

            return self::SUCCESS;
        }

        $sealed = fn () => DB::table('watchtower_alert_digest')->where('sealed', true)->where('id', '<=', $ceiling);
        $digest = $this->digest($sealed, (bool) ($config['digest']['instant'] ?? true));
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

        $sealed()->delete();

        $addresses = array_sum($digest['totals']);
        $this->info("Sent the digest: {$addresses} address(es).");

        return self::SUCCESS;
    }

    /**
     * Everything in the database: the listing is the top MAX_ENTRIES, and the
     * totals are counts, so a day of a thousand addresses costs fifty rows
     * here, not a thousand.
     *
     * @param  \Closure(): Builder  $sealed
     * @return array<string, mixed>
     */
    private function digest(\Closure $sealed, bool $instant): array
    {
        $group = ['type', 'ip', 'scope', 'reason', 'not_blocked_because'];

        // Blocks first ('blocked' sorts before 'would_have_blocked'), then
        // the busiest.
        $entries = $sealed()
            ->select($group)
            ->selectRaw('sum(events) as events, sum(held_back) as held_back, min(first_at) as first_at, max(last_at) as last_at')
            ->groupBy($group)
            ->orderBy('type')
            ->orderByRaw('sum(events) desc')
            ->orderBy('ip')
            ->limit(self::MAX_ENTRIES)
            ->get()
            ->map(fn ($row) => [
                'type'                => $row->type,
                'ip'                  => $row->ip,
                'scope'               => $row->scope === BlockScope::GLOBAL ? null : $row->scope,
                'reason'              => $row->reason,
                'not_blocked_because' => $row->not_blocked_because,
                'events'              => (int) $row->events,
                'held_back'           => (int) $row->held_back,
                'first_at'            => (string) $row->first_at,
                'last_at'             => (string) $row->last_at,
            ])
            ->all();

        $groups = DB::query()->fromSub($sealed()->select($group)->groupBy($group), 'g')->count();

        $totals = DB::query()
            ->fromSub($sealed()->select(['type', 'ip', 'scope'])->groupBy(['type', 'ip', 'scope']), 'a')
            ->select('type')
            ->selectRaw('count(*) as addresses')
            ->groupBy('type')
            ->pluck('addresses', 'type');

        return [
            'since'   => (string) $sealed()->min('first_at'),
            'instant' => $instant,
            'totals'  => [
                'blocked'            => (int) ($totals['blocked'] ?? 0),
                'would_have_blocked' => (int) ($totals['would_have_blocked'] ?? 0),
            ],
            'entries' => $entries,
            'omitted' => max(0, $groups - count($entries)),
            'url'     => AlertChannels::link(),
        ];
    }
}
