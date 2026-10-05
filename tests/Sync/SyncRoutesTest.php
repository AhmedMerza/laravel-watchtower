<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Str;
use Watchtower\Enums\BlockSource;
use Watchtower\Events\IpBlocked;
use Watchtower\Http\Controllers\SyncController;
use Watchtower\Jobs\PushBlockToMaster;
use Watchtower\Models\BlacklistedIp;
use Watchtower\Services\BlacklistCache;
use Watchtower\Services\BlacklistService;
use Watchtower\Support\BlockScope;
use Watchtower\Support\SyncSignature;

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

    // The query string travels too: it carries the pull's paging cursor.
    $query = parse_url($request->url(), PHP_URL_QUERY);

    return $test->call(
        $request->method(),
        parse_url($request->url(), PHP_URL_PATH).($query ? "?{$query}" : ''),
        [], [], [],
        $server,
        $request->body()
    );
}

it('404s a validly signed request on a satellite whose route table still has the routes', function () {
    // What a route cache built on the master leaves behind: the routes exist,
    // but this environment is a satellite and must not serve them (#36).
    config()->set('watchtower.sync.role', 'satellite');

    $this->withHeaders(signedHeaders('GET', SyncSignature::PULL_PATH, ''))
        ->get(SyncSignature::PULL_PATH)
        ->assertNotFound();
});

it('serves a validly signed pull on the master', function () {
    config()->set('watchtower.sync.role', 'master');

    $this->withHeaders(signedHeaders('GET', SyncSignature::PULL_PATH, ''))
        ->get(SyncSignature::PULL_PATH)
        ->assertOk();
});

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

/** Write $count global manual blocks straight to the DB, in one insert. */
function seedMasterBlocks(int $count): void
{
    BlacklistedIp::insert(array_map(fn (int $i) => [
        'id'         => (string) Str::ulid(),
        'ip'         => long2ip(0x0A000000 + $i),
        'scope'      => BlockScope::GLOBAL,
        'source'     => BlockSource::Manual->value,
        'source_env' => 'production',
        'created_at' => now(),
        'updated_at' => now(),
    ], range(1, $count)));
}

it('pages a pull that asks for pages, and ends on a null cursor', function () {
    seedMasterBlocks(SyncController::PAGE_SIZE + 1);

    $first = $this->withHeaders(signedHeaders('GET', SyncSignature::PULL_PATH))
        ->get(SyncSignature::PULL_PATH.'?after=0')
        ->assertOk()
        ->assertJsonCount(SyncController::PAGE_SIZE, 'data');

    $cursor = $first->json('next_cursor');
    expect($cursor)->toBe(BlacklistedIp::orderBy('id')->skip(SyncController::PAGE_SIZE - 1)->value('id'));

    $this->withHeaders(signedHeaders('GET', SyncSignature::PULL_PATH))
        ->get(SyncSignature::PULL_PATH."?after={$cursor}")
        ->assertOk()
        ->assertJsonCount(1, 'data')
        ->assertJsonPath('data.0.ip', BlacklistedIp::orderByDesc('id')->value('ip'))
        ->assertJsonPath('next_cursor', null);
});

it('sends the whole list to a satellite too old to ask for pages', function () {
    // Such a satellite reads only `data`; a first page alone would silently
    // drop the rest of the blocklist from it.
    seedMasterBlocks(SyncController::PAGE_SIZE + 1);

    $this->withHeaders(signedHeaders('GET', SyncSignature::PULL_PATH))
        ->get(SyncSignature::PULL_PATH)
        ->assertOk()
        ->assertJsonCount(SyncController::PAGE_SIZE + 1, 'data')
        ->assertJsonMissingPath('next_cursor');
});

it('sends only the columns a satellite reads', function () {
    BlacklistedIp::create(['ip' => '1.2.3.4', 'source' => BlockSource::Manual, 'source_env' => 'production']);

    $row = $this->withHeaders(signedHeaders('GET', SyncSignature::PULL_PATH))
        ->get(SyncSignature::PULL_PATH.'?after=0')
        ->assertOk()
        ->json('data.0');

    expect(array_keys($row))->toEqualCanonicalizing(['ip', 'reason', 'source_env', 'source', 'expires_at', 'blocked_by']);
});

it('rejects a malformed cursor', function () {
    $this->withHeaders(signedHeaders('GET', SyncSignature::PULL_PATH) + ['Accept' => 'application/json'])
        ->get(SyncSignature::PULL_PATH.'?after[]=x')
        ->assertStatus(422);
});

it('round-trips a pull longer than one page through the real route and middleware', function () {
    seedMasterBlocks(SyncController::PAGE_SIZE + 1);
    Cache::flush();

    Http::fake(function ($request) {
        $replayed = replaySyncRequest($this, $request);

        return Http::response($replayed->getContent(), $replayed->getStatusCode());
    });

    // The rows are already here (master and satellite share one DB in the
    // test), so they count as skipped — what matters is every page was read
    // and the last row made it into the cache.
    $this->artisan('watchtower:sync')->assertSuccessful();

    Http::assertSentCount(2);
    expect(app(BlacklistService::class)->isBlocked(BlacklistedIp::orderByDesc('id')->value('ip')))->toBeTrue();
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

it('records a pushed range, however broad, without force', function () {
    // The satellite already decided, with or without force. Refusing it here
    // would leave the two environments disagreeing.
    postSigned($this, json_encode(['ip' => '10.0.0.0/8', 'source_env' => 'staging']))
        ->assertOk()
        ->assertJsonPath('data.ip', '10.0.0.0/8');
});

it('stores a bare IPv6 address pushed by an older satellite as the master\'s prefix', function () {
    BlacklistedIp::create(['ip' => '2001:db8::/64', 'source' => BlockSource::Manual, 'source_env' => 'master']);

    // The /64 is already a local manual block, so the push must not replace it.
    postSigned($this, json_encode(['ip' => '2001:db8::1', 'source_env' => 'staging']))
        ->assertOk()
        ->assertJsonPath('applied', false);

    $this->assertDatabaseCount('blacklisted_ips', 1);
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

it('blocks the address in the cache, not just in the table', function () {
    postSigned($this, json_encode(['ip' => '5.6.7.8', 'source_env' => 'staging']))->assertOk();

    // The row goes, so the cache has to answer on its own. Without this the
    // assertion below proves nothing: isBlocked() warms itself from the DB
    // when it finds no ranges key, so it would report the address blocked
    // whether or not the push ever wrote a cache entry. A key written by
    // put() survives that warm, being deliberately outside the rebuild index.
    BlacklistedIp::where('ip', '5.6.7.8')->delete();

    // BlockedIpMiddleware reads the cache and never the DB, so a push that
    // wrote the row and missed the cache entry would leave the address
    // reaching the app while every other assertion here still passed.
    expect((new BlacklistCache)->isBlocked('5.6.7.8'))->toBeTrue();
});

it('announces a block a satellite pushes here', function () {
    Event::fake([IpBlocked::class]);

    postSigned($this, json_encode(['ip' => '5.6.7.8', 'source_env' => 'staging']))->assertOk();

    // The other half of the rule watchtower:sync relies on: a block is
    // announced once, by the environment that received it. This is that
    // environment, so the webhook fires here and nowhere else.
    Event::assertDispatched(IpBlocked::class, fn ($e) => $e->record->ip === '5.6.7.8');
});

it('announces nothing when the push is refused as a downgrade', function () {
    Event::fake([IpBlocked::class]);

    BlacklistedIp::create(['ip' => '5.6.7.8', 'source' => BlockSource::Manual, 'source_env' => 'production']);

    postSigned($this, json_encode(['ip' => '5.6.7.8', 'source_env' => 'staging']))
        ->assertOk()
        ->assertJsonPath('applied', false);

    Event::assertNotDispatched(IpBlocked::class);
});

it('refuses a pushed IP that is in the master never-block list', function () {
    config()->set('watchtower.never_block', ['10.0.0.1']);

    postSigned($this, json_encode(['ip' => '10.0.0.1', 'source_env' => 'staging']))
        ->assertStatus(422);

    $this->assertDatabaseCount('blacklisted_ips', 0);
});

it('answers 500, not the never-block 422, when the master cannot write the block', function () {
    // A satellite retries either one, but only a 500 tells it the master is
    // failing rather than refusing the IP.
    failBlacklistInserts();

    postSigned($this, json_encode(['ip' => '10.0.0.1', 'source_env' => 'staging']))
        ->assertStatus(500);
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
        'ip'         => 'not-an-ip',
        'source'     => BlockSource::Manual,
        'source_env' => 'staging',
    ]);

    expect(fn () => (new PushBlockToMaster($record))->handle())
        ->toThrow(RuntimeException::class);

    expect($status)->toBe(422);

    $this->assertDatabaseCount('blacklisted_ips', 0);
});

it('clips an over-long reason to what the master accepts', function () {
    // reason is a text column locally but the master validates it at 500. A
    // block that never propagates is worse than one with a clipped reason.
    Http::fake(function ($request) {
        $replayed = replaySyncRequest($this, $request);

        return Http::response($replayed->getContent(), $replayed->getStatusCode());
    });

    (new PushBlockToMaster(new BlacklistedIp([
        'ip'         => '9.9.9.9',
        'reason'     => str_repeat('a', 900),
        'source'     => BlockSource::Manual,
        'source_env' => 'staging',
    ])))->handle();

    $stored = BlacklistedIp::where('ip', '9.9.9.9')->firstOrFail();

    expect(mb_strlen((string) $stored->reason))->toBe(500)
        ->and($stored->reason)->toEndWith('...');
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
