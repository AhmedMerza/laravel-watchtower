<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Queue;
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

    $global = BlacklistedIp::create(['ip' => '1.2.3.4', 'scope' => BlockScope::GLOBAL, 'source' => BlockSource::Manual]);
    BlacklistedIp::create(['ip' => '5.6.7.8', 'scope' => 'auth', 'source' => BlockSource::Manual]);

    $this->artisan('watchtower:reconcile')
        ->assertSuccessful()
        ->expectsOutputToContain('Reconciled laravel.');

    // The scoped row must not reach a target that has no notion of scope —
    // same guard as the live path's, just exercised from the full-set side.
    Queue::assertPushed(PushBlockToMaster::class, fn ($job) => $job->record->is($global));
    Queue::assertPushed(PushBlockToMaster::class, 1);
});

it('does not reconcile an expired block', function () {
    Queue::fake();
    config()->set('watchtower.sync.master_url', 'https://master.example.com');

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
