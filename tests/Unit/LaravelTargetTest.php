<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Queue;
use Watchtower\Enums\BlockSource;
use Watchtower\Jobs\PushBlockToMaster;
use Watchtower\Models\BlacklistedIp;
use Watchtower\Targets\LaravelTarget;

beforeEach(function () {
    $this->target = new LaravelTarget;
});

it('dispatches PushBlockToMaster when master URL is configured', function () {
    Queue::fake();
    config()->set('watchtower.sync.master_url', 'https://master.example.com');

    $record = BlacklistedIp::create(['ip' => '1.2.3.4', 'source' => BlockSource::Manual]);

    $this->target->apply($record);

    Queue::assertPushed(PushBlockToMaster::class, fn ($job) => $job->record->is($record));
});

it('pushes to master on the queue sync.queue names', function () {
    Queue::fake();
    config()->set('watchtower.sync.master_url', 'https://master.example.com');
    config()->set('watchtower.sync.queue', 'sync');

    $record = BlacklistedIp::create(['ip' => '1.2.3.4', 'source' => BlockSource::Manual]);

    $this->target->apply($record);

    Queue::assertPushedOn('sync', PushBlockToMaster::class);
});

it('does not dispatch when master URL is not configured', function () {
    Queue::fake();
    config()->set('watchtower.sync.master_url', null);

    $record = BlacklistedIp::create(['ip' => '1.2.3.4', 'source' => BlockSource::Manual]);

    $this->target->apply($record);

    Queue::assertNotPushed(PushBlockToMaster::class);
});

it('does not dispatch a block that arrived by sync, even via reconcile', function () {
    // The anti-loop guard matters most here: reconcile() walks every active
    // record, Sync-sourced ones included on a satellite, and PushBlockToMaster
    // would just no-op anyway — this is what skips the wasted queue round trip.
    Queue::fake();
    config()->set('watchtower.sync.master_url', 'https://master.example.com');

    $record = BlacklistedIp::create(['ip' => '1.2.3.4', 'source' => BlockSource::Sync]);

    $this->target->apply($record);

    Queue::assertNotPushed(PushBlockToMaster::class);
});

it('does nothing on remove — no push-based unblock exists today', function () {
    Queue::fake();
    config()->set('watchtower.sync.master_url', 'https://master.example.com');

    $this->target->remove('1.2.3.4');

    Queue::assertNothingPushed();
});

it('reconciles by re-pushing every given record', function () {
    Queue::fake();
    config()->set('watchtower.sync.master_url', 'https://master.example.com');

    $a = BlacklistedIp::create(['ip' => '1.2.3.4', 'source' => BlockSource::Manual]);
    $b = BlacklistedIp::create(['ip' => '5.6.7.8', 'source' => BlockSource::Auto]);

    $this->target->reconcile([$a, $b]);

    Queue::assertPushed(PushBlockToMaster::class, 2);
    Queue::assertPushed(PushBlockToMaster::class, fn ($job) => $job->record->is($a));
    Queue::assertPushed(PushBlockToMaster::class, fn ($job) => $job->record->is($b));
});

it('skips Sync-sourced records during reconcile', function () {
    Queue::fake();
    config()->set('watchtower.sync.master_url', 'https://master.example.com');

    $synced = BlacklistedIp::create(['ip' => '1.2.3.4', 'source' => BlockSource::Sync]);
    $manual = BlacklistedIp::create(['ip' => '5.6.7.8', 'source' => BlockSource::Manual]);

    $this->target->reconcile([$synced, $manual]);

    Queue::assertPushed(PushBlockToMaster::class, 1);
    Queue::assertPushed(PushBlockToMaster::class, fn ($job) => $job->record->is($manual));
});
