<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Route;
use Watchtower\Enums\BlockSource;
use Watchtower\Jobs\PushBlockToMaster;
use Watchtower\Models\BlacklistedIp;
use Watchtower\Services\BlacklistService;
use Watchtower\Support\SyncSignature;

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

/**
 * Replay an outgoing HTTP client request back into this app, so the client's
 * real signature meets the real route and the real middleware. Http::fake()
 * on its own never reaches either.
 */
function replaySyncRequest(object $test, object $request): object
{
    $server = [];

    foreach ($request->headers() as $name => $values) {
        $key = strtoupper(str_replace('-', '_', $name));

        $server[in_array($key, ['CONTENT_TYPE', 'CONTENT_LENGTH'], true) ? $key : 'HTTP_'.$key] = $values[0];
    }

    return $test->call(
        $request->method(),
        (string) parse_url($request->url(), PHP_URL_PATH),
        [], [], [],
        $server,
        $request->body()
    );
}

it('rejects an unsigned pull', function () {
    $this->get(SyncSignature::PULL_PATH)
        ->assertStatus(401)
        ->assertJsonPath('error', 'Missing sync signature headers.');
});

it('rejects an unsigned push', function () {
    $this->postJson(SyncSignature::PUSH_PATH, ['ip' => '1.2.3.4'])->assertStatus(401);

    $this->assertDatabaseCount('blacklisted_ips', 0);
});

it('rejects a signature made with the wrong secret', function () {
    $this->withHeaders(signedHeaders('GET', SyncSignature::PULL_PATH, '', ['secret' => 'not-the-secret']))
        ->get(SyncSignature::PULL_PATH)
        ->assertStatus(401)
        ->assertJsonPath('error', 'Invalid sync signature.');
});

it('rejects a tampered body', function () {
    postSigned($this, json_encode(['ip' => '1.2.3.4']), [
        'sendBody' => json_encode(['ip' => '9.9.9.9']),
    ])->assertStatus(401);

    $this->assertDatabaseCount('blacklisted_ips', 0);
});

it('rejects a stale timestamp so a captured request cannot be replayed later', function () {
    $stale = (string) now()->subMinutes(10)->timestamp;

    $this->withHeaders(signedHeaders('GET', SyncSignature::PULL_PATH, '', ['timestamp' => $stale]))
        ->get(SyncSignature::PULL_PATH)
        ->assertStatus(401)
        ->assertJsonPath('error', 'Sync timestamp outside the accepted window.');
});

it('rejects a timestamp from the future beyond the window', function () {
    $ahead = (string) now()->addMinutes(10)->timestamp;

    $this->withHeaders(signedHeaders('GET', SyncSignature::PULL_PATH, '', ['timestamp' => $ahead]))
        ->get(SyncSignature::PULL_PATH)
        ->assertStatus(401);
});

it('rejects a non-numeric timestamp', function () {
    $this->withHeaders(signedHeaders('GET', SyncSignature::PULL_PATH, '', ['timestamp' => 'not-a-number']))
        ->get(SyncSignature::PULL_PATH)
        ->assertStatus(401)
        ->assertJsonPath('error', 'Malformed sync timestamp.');
});

// The next two vary exactly ONE field of the signed string and hold the rest
// constant. An earlier version of this test changed the method, the path AND
// the body at once, so the body mismatch alone failed hash_equals() and it
// would have passed with the method/path binding deleted outright.

it('binds the path into the signature', function () {
    // Same method, same empty body — only the path the signature was made for
    // differs.
    $this->withHeaders(signedHeaders('GET', SyncSignature::PUSH_PATH))
        ->get(SyncSignature::PULL_PATH)
        ->assertStatus(401)
        ->assertJsonPath('error', 'Invalid sync signature.');
});

it('binds the method into the signature, so a captured read is not a write', function () {
    // Same path, same body — only the method the signature was made for
    // differs.
    postSigned($this, json_encode(['ip' => '1.2.3.4']), ['method' => 'GET'])
        ->assertStatus(401)
        ->assertJsonPath('error', 'Invalid sync signature.');

    $this->assertDatabaseCount('blacklisted_ips', 0);
});

it('serves the active blocklist to a correctly signed pull', function () {
    BlacklistedIp::create(['ip' => '1.2.3.4', 'source' => BlockSource::Manual, 'source_env' => 'production']);

    $this->withHeaders(signedHeaders('GET', SyncSignature::PULL_PATH))
        ->get(SyncSignature::PULL_PATH)
        ->assertOk()
        ->assertJsonPath('data.0.ip', '1.2.3.4');
});

it('records a correctly signed push', function () {
    postSigned($this, json_encode(['ip' => '5.6.7.8', 'reason' => 'brute force', 'source_env' => 'staging']))
        ->assertOk()
        ->assertJsonPath('applied', true);

    $this->assertDatabaseHas('blacklisted_ips', [
        'ip'         => '5.6.7.8',
        'source'     => 'sync',
        'source_env' => 'staging',
    ]);
});

it('updates an existing sync-sourced block on a repeat push', function () {
    // The steady state: a second satellite reporting the same IP, or the same
    // one pushing a new reason or expiry for an IP the master already has.
    BlacklistedIp::create([
        'ip'         => '5.6.7.8',
        'reason'     => 'first report',
        'source'     => BlockSource::Sync,
        'source_env' => 'staging',
    ]);

    postSigned($this, json_encode(['ip' => '5.6.7.8', 'reason' => 'still at it', 'source_env' => 'alpha']))
        ->assertOk()
        ->assertJsonPath('applied', true);

    $this->assertDatabaseCount('blacklisted_ips', 1);
    $this->assertDatabaseHas('blacklisted_ips', [
        'ip'         => '5.6.7.8',
        'reason'     => 'still at it',
        'source'     => 'sync',
        'source_env' => 'alpha',
    ]);
});

it('rejects an invalid payload with a 422', function () {
    postSigned($this, json_encode(['ip' => 'not-an-ip', 'source_env' => 'staging']))
        ->assertStatus(422)
        ->assertJsonStructure(['errors' => ['ip']]);

    $this->assertDatabaseCount('blacklisted_ips', 0);
});

it('does not let an incoming push downgrade a local manual block', function () {
    BlacklistedIp::create([
        'ip'         => '5.6.7.8',
        'reason'     => 'blocked here by hand',
        'source'     => BlockSource::Manual,
        'source_env' => 'production',
    ]);

    postSigned($this, json_encode(['ip' => '5.6.7.8', 'reason' => 'from a satellite', 'source_env' => 'staging']))
        ->assertOk()
        ->assertJsonPath('applied', false);

    $this->assertDatabaseHas('blacklisted_ips', [
        'ip'     => '5.6.7.8',
        'source' => 'manual',
        'reason' => 'blocked here by hand',
    ]);
});

it('refuses a pushed IP that is in the master never-block list', function () {
    config()->set('watchtower.never_block', ['10.0.0.1']);

    postSigned($this, json_encode(['ip' => '10.0.0.1', 'source_env' => 'staging']))
        ->assertStatus(422);

    $this->assertDatabaseCount('blacklisted_ips', 0);
});

it('shares no method and URI with a management route', function () {
    $syncRoutes = [];
    $otherRoutes = [];

    foreach (Route::getRoutes() as $route) {
        $target = str_starts_with($route->getName() ?? '', 'watchtower.sync.') ? 'syncRoutes' : 'otherRoutes';

        foreach ($route->methods() as $method) {
            ${$target}[] = $method.' '.$route->uri();
        }
    }

    expect($syncRoutes)->not->toBeEmpty()
        ->and(array_intersect($syncRoutes, $otherRoutes))->toBeEmpty();
});

it('round-trips a pushed block through the real route and middleware', function () {
    $status = null;

    Http::fake(function ($request) use (&$status) {
        $replayed = replaySyncRequest($this, $request);
        $status = $replayed->getStatusCode();

        return Http::response($replayed->getContent(), $status);
    });

    // Unsaved: it stands in for a block made on a satellite, which the
    // master has never seen.
    $record = new BlacklistedIp([
        'ip'         => '9.9.9.9',
        'reason'     => 'brute force',
        'source'     => BlockSource::Manual,
        'source_env' => 'staging',
    ]);

    (new PushBlockToMaster($record))->handle();

    expect($status)->toBe(200);

    // source_env is the pushing environment's own, stamped by the job —
    // 'testing' here — not whatever the record happened to carry.
    $this->assertDatabaseHas('blacklisted_ips', [
        'ip'         => '9.9.9.9',
        'reason'     => 'brute force',
        'source'     => 'sync',
        'source_env' => 'testing',
    ]);
});

it('surfaces a rejected push instead of reporting success', function () {
    // Laravel renders a ValidationException as a 302 unless the request asks
    // for JSON, and the HTTP client follows redirects by default — so without
    // the Accept header the client would land on the master's home page, read
    // 2xx as success, and drop the block on the floor. reason is a text column
    // but the receiver caps it at 500, so an auto-block with a long reason is
    // a real way to reach this.
    $status = null;

    Http::fake(function ($request) use (&$status) {
        $replayed = replaySyncRequest($this, $request);
        $status = $replayed->getStatusCode();

        return Http::response($replayed->getContent(), $status);
    });

    $record = new BlacklistedIp([
        'ip'         => '9.9.9.9',
        'reason'     => str_repeat('a', 501),
        'source'     => BlockSource::Manual,
        'source_env' => 'staging',
    ]);

    expect(fn () => (new PushBlockToMaster($record))->handle())
        ->toThrow(RuntimeException::class);

    expect($status)->toBe(422);

    $this->assertDatabaseCount('blacklisted_ips', 0);
});

it('round-trips watchtower:sync through the real route and middleware', function () {
    BlacklistedIp::create([
        'ip'         => '4.4.4.4',
        'reason'     => 'from master',
        'source'     => BlockSource::Sync,
        'source_env' => 'production',
    ]);

    // The record was written straight to the DB, so a hit below can only
    // come from the rebuild the command performs.
    Cache::flush();

    Http::fake(function ($request) {
        $replayed = replaySyncRequest($this, $request);

        return Http::response($replayed->getContent(), $replayed->getStatusCode());
    });

    $this->artisan('watchtower:sync')
        ->assertSuccessful()
        ->expectsOutputToContain('Synced 1 IPs');

    expect(app(BlacklistService::class)->isBlocked('4.4.4.4'))->toBeTrue();
});
