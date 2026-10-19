<?php

declare(strict_types=1);

namespace Watchtower\Support;

use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;

/**
 * The signal log (#138): every signal a real-time detector counted, kept so
 * a detector can be replayed at other settings. Off by default.
 *
 * Rows are buffered for the request and written in one insert once the
 * response has gone out — the provider flushes this from
 * `app()->terminating()` — so a detector never waits on the database, and a
 * database that is down costs the log rows, never the request or the block
 * decision.
 */
class SignalLog
{
    public const TABLE = 'watchtower_signals';

    /** @var list<array<string, mixed>> */
    private array $rows = [];

    /**
     * @param  array{path?: ?string, status?: ?int, target_hash?: ?string, target_user_id?: int|string|null, guard?: ?string}  $signal
     */
    public function push(string $detector, string $ip, int|string|null $userId, array $signal): void
    {
        if (! config('watchtower.auto_block.signal_log.enabled', false)) {
            return;
        }

        $path = $signal['path'] ?? null;
        $targetUserId = $signal['target_user_id'] ?? null;

        $this->rows[] = [
            'detector'       => $detector,
            'ip'             => $ip,
            'user_id'        => $userId === null ? null : (string) $userId,
            'path'           => $path === null ? null : mb_substr($path, 0, 255),
            'status'         => $signal['status'] ?? null,
            'target_hash'    => $signal['target_hash'] ?? null,
            'target_user_id' => $targetUserId === null ? null : (string) $targetUserId,
            'guard'          => $signal['guard'] ?? null,
            'occurred_at'    => now(),
        ];
    }

    public function flush(): void
    {
        if ($this->rows === []) {
            return;
        }

        $rows = $this->rows;
        $this->rows = [];

        try {
            DB::table(self::TABLE)->insert($rows);
        } catch (\Throwable $e) {
            // Logged once a minute at most: a missing table or a database
            // outage would otherwise log on every request that counted
            // something.
            if (FailureWindow::isOpen('signal_log')) {
                return;
            }

            FailureWindow::open('signal_log');

            try {
                Log::channel(config('watchtower.log_channel', 'stack'))
                    ->warning('Watchtower: could not write the signal log, dropping '.count($rows).' signal(s)', [
                        'error' => $e->getMessage(),
                    ]);
            } catch (\Throwable) {
                // A broken log channel must not fail the request's teardown.
            }
        }
    }

    /**
     * The keyed hash a failed login is logged under: the same for every
     * attempt at one identifier, whatever its case or stray spaces, and
     * useless without the app key.
     *
     * Every credential except the password goes in, sorted by key, so an
     * app that signs in by email, by username, or by phone and tenant
     * hashes whatever its identifier is.
     *
     * @param  array<mixed>  $credentials
     */
    public static function targetHash(array $credentials): ?string
    {
        $key = config('app.key');

        unset($credentials['password']);

        $identifier = array_map(
            static fn ($value): string => mb_strtolower(trim((string) $value)),
            array_filter($credentials, is_scalar(...)),
        );

        if (! is_string($key) || $key === '' || $identifier === []) {
            return null;
        }

        ksort($identifier);

        return hash_hmac('sha256', (string) json_encode($identifier), 'watchtower-signal-log|'.$key);
    }
}
