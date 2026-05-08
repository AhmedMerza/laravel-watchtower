<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Http;
use Watchtower\Models\BlacklistedIp;

beforeEach(function () {
    config()->set('cache.default', 'array');
    config()->set('watchtower.cache.store', 'array');
    Cache::flush();

    config()->set('watchtower.sync.master_url', 'https://master.example.com');
    config()->set('watchtower.sync.secret', 'test-secret');
});

it('syncs IPs from master and upserts them locally', function () {
    Http::fake([
        'master.example.com/watchtower/api/blacklist' => Http::response([
            'data' => [
                ['ip' => '1.2.3.4', 'reason' => 'synced', 'source_env' => 'production', 'expires_at' => null, 'blocked_by' => null, 'log_entry_id' => null],
                ['ip' => '5.6.7.8', 'reason' => null, 'source_env' => 'production', 'expires_at' => null, 'blocked_by' => null, 'log_entry_id' => null],
            ],
        ], 200),
    ]);

    $this->artisan('watchtower:sync')
        ->assertSuccessful()
        ->expectsOutputToContain('Synced 2 IPs');

    $this->assertDatabaseHas('blacklisted_ips', ['ip' => '1.2.3.4', 'source' => 'sync']);
    $this->assertDatabaseHas('blacklisted_ips', ['ip' => '5.6.7.8', 'source' => 'sync']);
});

it('fails gracefully when master returns an error', function () {
    Http::fake([
        'master.example.com/watchtower/api/blacklist' => Http::response([], 500),
    ]);

    $this->artisan('watchtower:sync')
        ->assertFailed()
        ->expectsOutputToContain('HTTP 500');
});

it('fails gracefully when master URL is not configured', function () {
    config()->set('watchtower.sync.master_url', null);

    $this->artisan('watchtower:sync')
        ->assertFailed()
        ->expectsOutputToContain('WATCHTOWER_MASTER_URL');
});

it('does not duplicate records on repeated syncs', function () {
    Http::fake([
        'master.example.com/watchtower/api/blacklist' => Http::response([
            'data' => [
                ['ip' => '1.2.3.4', 'reason' => 'initial', 'source_env' => 'production', 'expires_at' => null, 'blocked_by' => null, 'log_entry_id' => null],
            ],
        ], 200),
    ]);

    $this->artisan('watchtower:sync');
    $this->artisan('watchtower:sync');

    $this->assertDatabaseCount('blacklisted_ips', 1);
});
