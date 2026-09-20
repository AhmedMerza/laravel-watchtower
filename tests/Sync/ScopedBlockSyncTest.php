<?php

declare(strict_types=1);

use Watchtower\Enums\BlockSource;
use Watchtower\Models\BlacklistedIp;
use Watchtower\Support\BlockScope;
use Watchtower\Support\SyncSignature;

// signedHeaders() is defined in SyncRoutesTest.php, which Pest loads for this
// directory too.

beforeEach(function () {
    config()->set('watchtower.scopes', ['auth']);

    BlacklistedIp::create([
        'ip'         => '10.0.0.1',
        'scope'      => 'auth',
        'source'     => BlockSource::Manual,
        'source_env' => 'testing',
    ]);

    BlacklistedIp::create([
        'ip'         => '10.0.0.2',
        'source'     => BlockSource::Manual,
        'source_env' => 'testing',
    ]);
});

it('serves only global blocks to a satellite pulling the blocklist', function () {
    // A satellite has its own route file. It may carry `watchtower:auth` on
    // completely different routes, or on none at all — and the payload has no
    // scope field, so a scoped row sent here arrives as a global block and
    // takes the address off the whole satellite. A scoped block silently
    // becoming a global one is the worst thing this feature could do.
    $response = $this->withHeaders(signedHeaders('GET', SyncSignature::PULL_PATH))
        ->get(SyncSignature::PULL_PATH)
        ->assertOk();

    expect(collect($response->json('data'))->pluck('ip')->all())->toBe(['10.0.0.2']);
});

it('stores a pushed block as global even when a scoped row exists for the address', function () {
    // The pull side writes with updateOrCreate on (ip, scope). Without the
    // scope in the match, a synced global block for 10.0.0.1 would find the
    // local `auth` row and overwrite it — turning a scoped block into an
    // app-wide one on the satellite.
    $this->assertDatabaseHas('blacklisted_ips', ['ip' => '10.0.0.1', 'scope' => 'auth']);

    BlacklistedIp::updateOrCreate(
        ['ip' => '10.0.0.1', 'scope' => BlockScope::GLOBAL],
        ['source' => BlockSource::Sync, 'source_env' => 'master']
    );

    expect(BlacklistedIp::where('ip', '10.0.0.1')->pluck('scope')->sort()->values()->all())
        ->toBe([BlockScope::GLOBAL, 'auth']);
});

it('accepts a satellite\'s global block even when a local scoped block exists for that address', function () {
    // The master holds its own scoped block for this address.
    BlacklistedIp::create([
        'ip'         => '10.0.0.3',
        'scope'      => 'auth',
        'source'     => BlockSource::Manual,
        'source_env' => 'testing',
    ]);

    postSigned($this, json_encode(['ip' => '10.0.0.3', 'reason' => 'from satellite']))
        ->assertOk()
        ->assertJsonPath('applied', true);

    // The never-downgrade guard must compare against the master's own GLOBAL
    // row, not any row. Matching the scoped row instead made its Manual
    // source trip the guard and silently refuse a legitimate app-wide block.
    $this->assertDatabaseHas('blacklisted_ips', [
        'ip'     => '10.0.0.3',
        'scope'  => BlockScope::GLOBAL,
        'source' => 'sync',
    ]);

    // …and the local scoped block is untouched.
    $this->assertDatabaseHas('blacklisted_ips', [
        'ip'     => '10.0.0.3',
        'scope'  => 'auth',
        'source' => 'manual',
    ]);
});
