<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Queue;
use Illuminate\Support\Str;
use Watchtower\Enums\BlockSource;
use Watchtower\Jobs\PushBlockToMaster;
use Watchtower\Models\BlacklistedIp;
use Watchtower\Support\BlockScope;
use Watchtower\Targets\LaravelTarget;

it('reports no block targets enabled on a vanilla install', function () {
    config()->set('watchtower.sync.master_url', null);

    $this->artisan('watchtower:reconcile')
        ->assertSuccessful()
        ->expectsOutputToContain('No block targets enabled.');
});

it('re-pushes every active global block to the laravel target', function () {
    Queue::fake();
    config()->set('watchtower.sync.master_url', 'https://master.example.com');
    config()->set('watchtower.sync.secret', 'test-secret');
    Http::fake(['master.example.com/*' => Http::response(['data' => []])]);

    $global = BlacklistedIp::create(['ip' => '1.2.3.4', 'scope' => BlockScope::GLOBAL, 'source' => BlockSource::Manual]);
    BlacklistedIp::create(['ip' => '5.6.7.8', 'scope' => 'auth', 'source' => BlockSource::Manual]);

    $this->artisan('watchtower:reconcile')
        ->assertSuccessful()
        ->expectsOutputToContain('Reconciled laravel: 1 pushed to master.');

    // The scoped row must not reach a target that has no notion of scope —
    // same guard as the live path's, just exercised from the full-set side.
    Queue::assertPushed(PushBlockToMaster::class, fn ($job) => $job->record->is($global));
    Queue::assertPushed(PushBlockToMaster::class, 1);
});

it('does not reconcile an expired block', function () {
    Queue::fake();
    config()->set('watchtower.sync.master_url', 'https://master.example.com');
    config()->set('watchtower.sync.secret', 'test-secret');
    Http::fake(['master.example.com/*' => Http::response(['data' => []])]);

    BlacklistedIp::create([
        'ip'         => '1.2.3.4',
        'scope'      => BlockScope::GLOBAL,
        'source'     => BlockSource::Manual,
        'expires_at' => now()->subMinute(),
    ]);

    $this->artisan('watchtower:reconcile')->assertSuccessful();

    Queue::assertNotPushed(PushBlockToMaster::class);
});

it('fails loudly when a target throws, so cron sees it', function () {
    config()->set('watchtower.sync.master_url', 'https://master.example.com');
    config()->set('watchtower.log_channel', 'stack');

    $mock = Mockery::mock(LaravelTarget::class);
    $mock->shouldReceive('reconcile')->once()->andThrow(new RuntimeException('cloudflare is down'));
    $this->app->instance(LaravelTarget::class, $mock);

    $this->artisan('watchtower:reconcile')
        ->assertFailed()
        ->expectsOutputToContain('Failed to reconcile laravel');
});

it('fails, queueing nothing, when the master\'s list cannot be read', function () {
    Queue::fake();
    config()->set('watchtower.sync.master_url', 'https://master.example.com');
    config()->set('watchtower.sync.secret', 'test-secret');
    Http::fake(['master.example.com/*' => Http::response([], 500)]);

    BlacklistedIp::create(['ip' => '1.2.3.4', 'scope' => BlockScope::GLOBAL, 'source' => BlockSource::Manual]);

    $this->artisan('watchtower:reconcile')
        ->assertFailed()
        ->expectsOutputToContain('Failed to reconcile laravel: master returned HTTP 500');

    Queue::assertNothingPushed();
});

it('reconciles a blocklist longer than one lazy chunk', function () {
    // lazyById() reads 1000 rows at a time, and LaravelTarget walks the set
    // twice: once to see whether there is anything of ours, once to compare.
    Queue::fake();
    config()->set('watchtower.sync.master_url', 'https://master.example.com');
    config()->set('watchtower.sync.secret', 'test-secret');
    Http::fake(['master.example.com/*' => Http::response(['data' => [['ip' => '10.0.0.1', 'expires_at' => null]]])]);

    $rows = [];
    for ($i = 1; $i <= 1001; $i++) {
        $rows[] = ['id' => (string) Str::ulid(), 'ip' => long2ip(0x0A000000 + $i), 'scope' => '', 'source' => 'manual', 'created_at' => now(), 'updated_at' => now()];
    }
    foreach (array_chunk($rows, 500) as $chunk) {
        BlacklistedIp::insert($chunk);
    }

    $this->artisan('watchtower:reconcile')->assertSuccessful();

    Queue::assertPushed(PushBlockToMaster::class, 1000);
    Queue::assertNotPushed(PushBlockToMaster::class, fn ($job) => $job->record->ip === '10.0.0.1');
    Queue::assertPushed(PushBlockToMaster::class, fn ($job) => $job->record->ip === '10.0.3.233');
});

it('reports the same push count on every run while master refuses a block', function () {
    // Master never stores what its never_block refuses, so the block reads
    // as missing — and is pushed again — on every run (#172).
    Queue::fake();
    config()->set('watchtower.sync.master_url', 'https://master.example.com');
    config()->set('watchtower.sync.secret', 'test-secret');
    Http::fake(['master.example.com/*' => Http::response(['data' => [['ip' => '1.2.3.4', 'expires_at' => null]]])]);

    BlacklistedIp::create(['ip' => '1.2.3.4', 'scope' => BlockScope::GLOBAL, 'source' => BlockSource::Manual]);
    BlacklistedIp::create(['ip' => '5.6.7.8', 'scope' => BlockScope::GLOBAL, 'source' => BlockSource::Auto]);

    Log::shouldReceive('channel')->andReturnSelf();
    Log::shouldReceive('warning')->twice()
        ->with('Watchtower: reconcile pushed blocks master was missing', ['target' => 'laravel', 'pushed' => 1]);

    foreach ([1, 2] as $run) {
        $this->artisan('watchtower:reconcile')
            ->assertSuccessful()
            ->expectsOutputToContain('Reconciled laravel: 1 pushed to master.');
    }

    Queue::assertPushed(PushBlockToMaster::class, 2);
});

it('logs nothing when master already holds every block', function () {
    Queue::fake();
    config()->set('watchtower.sync.master_url', 'https://master.example.com');
    config()->set('watchtower.sync.secret', 'test-secret');
    Http::fake(['master.example.com/*' => Http::response(['data' => [['ip' => '1.2.3.4', 'expires_at' => null]]])]);

    BlacklistedIp::create(['ip' => '1.2.3.4', 'scope' => BlockScope::GLOBAL, 'source' => BlockSource::Manual]);

    Log::shouldReceive('channel')->andReturnSelf();
    Log::shouldReceive('warning')->never();

    $this->artisan('watchtower:reconcile')
        ->assertSuccessful()
        ->expectsOutputToContain('Reconciled laravel: 0 pushed to master.');

    Queue::assertNothingPushed();
});
