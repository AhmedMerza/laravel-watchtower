<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Queue;
use Watchtower\Enums\BlockSource;
use Watchtower\Exceptions\MasterPullException;
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

it('does not dispatch on the master, which would push to itself', function () {
    Queue::fake();
    config()->set('watchtower.sync.master_url', 'https://master.example.com');
    config()->set('watchtower.sync.role', 'master');

    $this->target->apply(BlacklistedIp::create(['ip' => '1.2.3.4', 'source' => BlockSource::Manual]));

    Queue::assertNothingPushed();
});

it('dispatches on a satellite, and on an unrecognised role', function (string $role) {
    Queue::fake();
    config()->set('watchtower.sync.master_url', 'https://master.example.com');
    config()->set('watchtower.sync.role', $role);

    $this->target->apply(BlacklistedIp::create(['ip' => '1.2.3.4', 'source' => BlockSource::Manual]));

    Queue::assertPushed(PushBlockToMaster::class);
})->with(['satellite', 'sattelite']);

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

function fakeMaster(array $blocks): void
{
    config()->set('watchtower.sync.master_url', 'https://master.example.com');
    config()->set('watchtower.sync.secret', 'test-secret');

    Http::fake(['master.example.com/watchtower/sync/blocks*' => Http::response(['data' => $blocks, 'next_cursor' => null])]);
}

it('reconciles by pushing only the records master does not hold', function () {
    Queue::fake();
    fakeMaster([['ip' => '1.2.3.4', 'expires_at' => null]]);

    $held = BlacklistedIp::create(['ip' => '1.2.3.4', 'source' => BlockSource::Manual]);
    $missing = BlacklistedIp::create(['ip' => '5.6.7.8', 'source' => BlockSource::Auto]);

    $this->target->reconcile([$held, $missing]);

    Queue::assertPushed(PushBlockToMaster::class, 1);
    Queue::assertPushed(PushBlockToMaster::class, fn ($job) => $job->record->is($missing));
});

it('re-pushes a block master holds with an earlier expiry than ours', function (?string $ours, ?string $theirs, bool $pushed) {
    // Both expiries derive from now() and compare by the second.
    $this->freezeTime();
    Queue::fake();
    fakeMaster([['ip' => '1.2.3.4', 'expires_at' => $theirs === null ? null : now()->modify($theirs)->toJSON()]]);

    $record = BlacklistedIp::create([
        'ip'         => '1.2.3.4',
        'source'     => BlockSource::Auto,
        'expires_at' => $ours === null ? null : now()->modify($ours),
    ]);

    $this->target->reconcile([$record]);

    $pushed ? Queue::assertPushed(PushBlockToMaster::class, 1) : Queue::assertNotPushed(PushBlockToMaster::class);
})->with([
    'master lapses sooner'           => ['+2 hours', '+1 hour', true],
    'ours is permanent, master not'  => [null, '+1 hour', true],
    'same expiry'                    => ['+1 hour', '+1 hour', false],
    'master holds it longer'         => ['+1 hour', '+2 hours', false],
    'master holds it permanently'    => ['+1 hour', null, false],
    'both permanent'                 => [null, null, false],
]);

it('reads every page of master\'s list before deciding what to push', function () {
    Queue::fake();
    config()->set('watchtower.sync.master_url', 'https://master.example.com');
    config()->set('watchtower.sync.secret', 'test-secret');
    Http::fake(['master.example.com/watchtower/sync/blocks*' => Http::sequence()
        ->push(['data' => [['ip' => '1.1.1.1', 'expires_at' => null]], 'next_cursor' => '01J00000000000000000000001'])
        ->push(['data' => [['ip' => '2.2.2.2', 'expires_at' => null]], 'next_cursor' => null]),
    ]);

    $records = collect(['1.1.1.1', '2.2.2.2', '3.3.3.3'])
        ->map(fn ($ip) => BlacklistedIp::create(['ip' => $ip, 'source' => BlockSource::Manual]));

    $this->target->reconcile($records);

    Queue::assertPushed(PushBlockToMaster::class, 1);
    Queue::assertPushed(PushBlockToMaster::class, fn ($job) => $job->record->ip === '3.3.3.3');
    Http::assertSent(fn ($request) => $request['after'] === '01J00000000000000000000001');
});

it('matches a bare IPv6 row against the prefix master stores it under', function () {
    // An explicit /128 is stored bare here; master widens every push to
    // ipv6_block_prefix, so its list carries the /64.
    Queue::fake();
    fakeMaster([['ip' => '2001:db8::/64', 'expires_at' => null]]);

    $this->target->reconcile([BlacklistedIp::create(['ip' => '2001:db8::1', 'source' => BlockSource::Manual])]);

    Queue::assertNothingPushed();
});

it('skips master rows it cannot read without abandoning the rest', function () {
    Queue::fake();
    fakeMaster([
        ['expires_at' => null],
        ['ip' => ['5.6.7.8']],
        'not a row',
        ['ip' => '1.2.3.4', 'expires_at' => 'not a date'],
        ['ip' => '9.9.9.9', 'expires_at' => null],
    ]);

    $unreadable = BlacklistedIp::create(['ip' => '1.2.3.4', 'source' => BlockSource::Manual, 'expires_at' => now()->addHour()]);
    $missing = BlacklistedIp::create(['ip' => '5.6.7.8', 'source' => BlockSource::Manual]);
    $held = BlacklistedIp::create(['ip' => '9.9.9.9', 'source' => BlockSource::Manual]);

    $this->target->reconcile([$unreadable, $missing, $held]);

    // An expiry master sent but we can't parse counts as lapsed: push ours.
    Queue::assertPushed(PushBlockToMaster::class, 2);
    Queue::assertNotPushed(PushBlockToMaster::class, fn ($job) => $job->record->is($held));
});

it('skips Sync-sourced records during reconcile', function () {
    Queue::fake();
    fakeMaster([]);

    $synced = BlacklistedIp::create(['ip' => '1.2.3.4', 'source' => BlockSource::Sync]);
    $manual = BlacklistedIp::create(['ip' => '5.6.7.8', 'source' => BlockSource::Manual]);

    $this->target->reconcile([$synced, $manual]);

    Queue::assertPushed(PushBlockToMaster::class, 1);
    Queue::assertPushed(PushBlockToMaster::class, fn ($job) => $job->record->is($manual));
});

it('does not ask master anything when there is nothing of ours to repair', function () {
    Queue::fake();
    fakeMaster([]);

    $this->target->reconcile([BlacklistedIp::create(['ip' => '1.2.3.4', 'source' => BlockSource::Sync])]);
    $this->target->reconcile([]);

    Http::assertNothingSent();
});

it('does not reconcile on the master, or without a master URL', function (?string $url, ?string $role) {
    Queue::fake();
    fakeMaster([]);
    config()->set('watchtower.sync.master_url', $url);
    config()->set('watchtower.sync.role', $role);

    $this->target->reconcile([BlacklistedIp::create(['ip' => '1.2.3.4', 'source' => BlockSource::Manual])]);

    Http::assertNothingSent();
    Queue::assertNothingPushed();
})->with([
    'the master'     => ['https://master.example.com', 'master'],
    'no master URL'  => [null, null],
]);

it('fails reconcile, pushing nothing, when master\'s list cannot be read', function () {
    Queue::fake();
    config()->set('watchtower.sync.master_url', 'https://master.example.com');
    config()->set('watchtower.sync.secret', 'test-secret');
    Http::fake(['master.example.com/*' => Http::response([], 500)]);

    $record = BlacklistedIp::create(['ip' => '1.2.3.4', 'source' => BlockSource::Manual]);

    expect(fn () => $this->target->reconcile([$record]))->toThrow(MasterPullException::class, 'HTTP 500');
    Queue::assertNothingPushed();
});

it('fails reconcile when there is no sync secret to read master\'s list with', function () {
    Queue::fake();
    fakeMaster([]);
    config()->set('watchtower.sync.secret', '');

    $record = BlacklistedIp::create(['ip' => '1.2.3.4', 'source' => BlockSource::Manual]);

    expect(fn () => $this->target->reconcile([$record]))->toThrow(RuntimeException::class, 'WATCHTOWER_SYNC_SECRET');
    Http::assertNothingSent();
});
