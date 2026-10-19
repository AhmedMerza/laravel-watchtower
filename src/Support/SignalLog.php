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
            'path'           => $path === null ? null : self::cleanPath($path),
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
     * Every credential whose key doesn't contain "password" goes in, sorted
     * by key — the same rule Laravel's EloquentUserProvider uses to pick the
     * fields it looks a user up by — so an app that signs in by email, by
     * username, or by phone and tenant hashes whatever its identifier is,
     * and a `password_confirmation` or `current_password` never does.
     *
     * @param  array<mixed>  $credentials
     */
    public static function targetHash(array $credentials): ?string
    {
        $key = config('app.key');

        $identifier = array_map(
            static fn ($value): string => mb_strtolower(trim((string) $value)),
            array_filter(
                $credentials,
                static fn ($value, $name): bool => is_scalar($value) && ! str_contains((string) $name, 'password'),
                ARRAY_FILTER_USE_BOTH,
            ),
        );

        if (! is_string($key) || $key === '' || $identifier === []) {
            return null;
        }

        ksort($identifier);

        // SUBSTITUTE, because json_encode() returns false on invalid UTF-8,
        // and every such identifier would then hash the same empty string.
        return hash_hmac(
            'sha256',
            (string) json_encode($identifier, JSON_INVALID_UTF8_SUBSTITUTE),
            'watchtower-signal-log|'.$key,
        );
    }

    /**
     * The path as a column can hold it. It is the decoded path, so `/%FF`
     * or `/a%00b` arrive as invalid UTF-8 or a NUL byte, which MySQL and
     * Postgres refuse — and one refused row fails the request's whole
     * insert, which would let a scanner keep itself out of the log.
     */
    private static function cleanPath(string $path): string
    {
        return mb_substr(str_replace("\0", '', mb_scrub($path, 'UTF-8')), 0, 255);
    }
}
