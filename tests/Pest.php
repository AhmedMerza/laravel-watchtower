<?php

use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
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
