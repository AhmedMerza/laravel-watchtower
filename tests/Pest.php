<?php

use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use Watchtower\Support\SyncSignature;
use Watchtower\Tests\StandaloneTestCase;
use Watchtower\Tests\SyncTestCase;
use Watchtower\Tests\TestCase;

uses(TestCase::class)->in(__DIR__.'/Feature', __DIR__.'/Unit');

// A master environment. Sync routes are registered from config at boot, so
// these need the secret in place before the app comes up — which is what
// SyncTestCase does and a beforeEach() cannot.
uses(SyncTestCase::class)->in(__DIR__.'/Sync');

// An app without LogScope, where the management API sits behind the
// `viewWatchtower` Gate.
uses(StandaloneTestCase::class)->in(__DIR__.'/Standalone');

/**
 * Make every insert into blacklisted_ips throw a real QueryException, as a
 * failing database would, while reads keep working.
 */
function failBlacklistInserts(): void
{
    DB::statement("CREATE TRIGGER fail_blacklist_insert BEFORE INSERT ON blacklisted_ips BEGIN SELECT RAISE(ABORT, 'simulated write failure'); END");
}

/**
 * Make every write to every table this package owns abort, so that anything
 * claiming to be read-only can be held to it by the database rather than by
 * a reviewer's attention.
 *
 * Asserting "no writes" by counting rows afterwards only catches a write
 * that CHANGED something: a block re-inserted with identical values, or a
 * write inside a transaction that later rolled back, would pass a count and
 * still mean the command is not read-only. A trigger fails the moment the
 * statement is attempted, which is the property `watchtower:simulate`
 * actually promises.
 *
 * The log table is deliberately included. A backtest reads history; writing
 * to it would be corrupting the evidence.
 */
function failAllWatchtowerWrites(): void
{
    foreach (['blacklisted_ips', 'ip_offences', 'log_entries'] as $table) {
        foreach (['INSERT', 'UPDATE', 'DELETE'] as $event) {
            $name = 'readonly_'.strtolower($event).'_'.$table;

            DB::statement(
                "CREATE TRIGGER {$name} BEFORE {$event} ON {$table} "
                ."BEGIN SELECT RAISE(ABORT, 'write attempted on {$table}'); END"
            );
        }
    }
}

/**
 * A LogScope-shaped row for the log-driven auto-block rules to read.
 *
 * Shared rather than file-local: the scoped auto-block tests read the same
 * table, and a second copy would be one more thing to keep in step with
 * LogScope's own schema.
 */
function logEntry(string $ip, array $attributes = []): void
{
    DB::table('log_entries')->insert(array_merge([
        'id'          => Str::ulid(),
        'level'       => 'error',
        'message'     => 'Boom',
        'ip_address'  => $ip,
        'user_id'     => null,
        'occurred_at' => now(),
        'created_at'  => now(),
        'updated_at'  => now(),
    ], $attributes));
}

/**
 * Signed headers as a satellite would send them, with each part overridable
 * so a test can corrupt exactly one of them.
 */
function signedHeaders(string $method, string $path, string $body = '', array $override = []): array
{
    $timestamp = (string) ($override['timestamp'] ?? now()->timestamp);

    return [
        SyncSignature::TIMESTAMP_HEADER => $timestamp,
        SyncSignature::SIGNATURE_HEADER => $override['signature'] ?? SyncSignature::compute(
            $timestamp,
            $method,
            $path,
            $body,
            $override['secret'] ?? 'test-secret'
        ),
    ];
}

/**
 * A signed POST. postJson() can't be used: it re-encodes the array, and the
 * signature covers the exact bytes.
 */
function postSigned(object $test, string $body, array $override = []): object
{
    $headers = signedHeaders($override['method'] ?? 'POST', SyncSignature::PUSH_PATH, $body, $override);

    return $test->call('POST', SyncSignature::PUSH_PATH, [], [], [], [
        'CONTENT_TYPE'                => 'application/json',
        'HTTP_ACCEPT'                 => 'application/json',
        'HTTP_X_WATCHTOWER_TIMESTAMP' => $headers[SyncSignature::TIMESTAMP_HEADER],
        'HTTP_X_WATCHTOWER_SIGNATURE' => $headers[SyncSignature::SIGNATURE_HEADER],
    ], $override['sendBody'] ?? $body);
}
