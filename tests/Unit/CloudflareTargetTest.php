<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Log;
use Watchtower\Enums\BlockSource;
use Watchtower\Models\BlacklistedIp;
use Watchtower\Support\CloudflareApi;
use Watchtower\Targets\CloudflareTarget;

beforeEach(function () {
    $this->mockApi = Mockery::mock(CloudflareApi::class);
    $this->target = new CloudflareTarget($this->mockApi);
});

// --- apply() ---------------------------------------------------------------

it('creates a rule when none exists for the address', function () {
    $record = BlacklistedIp::create(['ip' => '1.2.3.4', 'source' => BlockSource::Manual]);

    $this->mockApi->shouldReceive('findRule')->once()->with('ip', '1.2.3.4')->andReturn(null);
    $this->mockApi->shouldReceive('create')->once()->with('ip', '1.2.3.4');

    $this->target->apply($record);
});

it('does not create a rule that already exists and is ours', function () {
    // Makes a retried apply() and a reconcile() replay idempotent.
    $record = BlacklistedIp::create(['ip' => '1.2.3.4', 'source' => BlockSource::Manual]);

    $this->mockApi->shouldReceive('findRule')->once()->andReturn([
        'id' => 'rule1', 'mode' => 'block', 'notes' => CloudflareApi::NOTE,
    ]);
    $this->mockApi->shouldNotReceive('create');

    $this->target->apply($record);
});

it('refuses to replace a rule for the same address that it did not create', function () {
    $record = BlacklistedIp::create(['ip' => '1.2.3.4', 'source' => BlockSource::Manual]);

    $this->mockApi->shouldReceive('findRule')->once()->andReturn([
        'id' => 'rule1', 'mode' => 'block', 'notes' => 'a note an admin wrote by hand',
    ]);
    $this->mockApi->shouldNotReceive('create');

    expect(fn () => $this->target->apply($record))->toThrow(RuntimeException::class);
});

it('refuses when its own rule exists in a mode other than block', function () {
    $record = BlacklistedIp::create(['ip' => '1.2.3.4', 'source' => BlockSource::Manual]);

    $this->mockApi->shouldReceive('findRule')->once()->andReturn([
        'id' => 'rule1', 'mode' => 'challenge', 'notes' => CloudflareApi::NOTE,
    ]);
    $this->mockApi->shouldNotReceive('create');

    expect(fn () => $this->target->apply($record))->toThrow(RuntimeException::class);
});

it('applies to a Sync-sourced record, unlike LaravelTarget', function () {
    // The anti-loop skip on LaravelTarget is specific to the master/satellite
    // echo risk; Cloudflare has no such risk, so a Sync-sourced global block
    // must still be pushed.
    $record = BlacklistedIp::create(['ip' => '1.2.3.4', 'source' => BlockSource::Sync]);

    $this->mockApi->shouldReceive('findRule')->once()->andReturn(null);
    $this->mockApi->shouldReceive('create')->once()->with('ip', '1.2.3.4');

    $this->target->apply($record);
});

it('resolves a supported CIDR range to the ip_range target', function () {
    $record = BlacklistedIp::create(['ip' => '2001:db8::/64', 'source' => BlockSource::Manual]);

    $this->mockApi->shouldReceive('findRule')->once()->with('ip_range', '2001:db8::/64')->andReturn(null);
    $this->mockApi->shouldReceive('create')->once()->with('ip_range', '2001:db8::/64');

    $this->target->apply($record);
});

it('throws on a CIDR prefix Cloudflare does not support, without calling the API', function () {
    $record = BlacklistedIp::create(['ip' => '203.0.113.0/20', 'source' => BlockSource::Manual]);

    $this->mockApi->shouldNotReceive('findRule');
    $this->mockApi->shouldNotReceive('create');

    expect(fn () => $this->target->apply($record))->toThrow(RuntimeException::class);
});

// --- remove() ----------------------------------------------------------------

it('deletes its own rule on remove', function () {
    $this->mockApi->shouldReceive('findRule')->once()->with('ip', '1.2.3.4')->andReturn([
        'id' => 'rule1', 'mode' => 'block', 'notes' => CloudflareApi::NOTE,
    ]);
    $this->mockApi->shouldReceive('delete')->once()->with('rule1');

    $this->target->remove('1.2.3.4');
});

it('does nothing on remove when no rule exists', function () {
    $this->mockApi->shouldReceive('findRule')->once()->andReturn(null);
    $this->mockApi->shouldNotReceive('delete');

    $this->target->remove('1.2.3.4');
});

it('never deletes a rule for the address that it did not create', function () {
    $this->mockApi->shouldReceive('findRule')->once()->andReturn([
        'id' => 'rule1', 'mode' => 'block', 'notes' => 'an admin wrote this by hand',
    ]);
    $this->mockApi->shouldNotReceive('delete');

    $this->target->remove('1.2.3.4');
});

// --- reconcile() ---------------------------------------------------------------

it('creates whatever is active but not yet managed, and leaves matches alone', function () {
    $a = BlacklistedIp::create(['ip' => '1.2.3.4', 'source' => BlockSource::Manual]);
    $b = BlacklistedIp::create(['ip' => '5.6.7.8', 'source' => BlockSource::Manual]);

    $this->mockApi->shouldReceive('listManaged')->once()->andReturn(['1.2.3.4' => 'rule1']);
    $this->mockApi->shouldReceive('create')->once()->with('ip', '5.6.7.8');
    $this->mockApi->shouldNotReceive('delete');

    $this->target->reconcile([$a, $b]);
});

it('deletes whatever is managed but no longer active', function () {
    $a = BlacklistedIp::create(['ip' => '1.2.3.4', 'source' => BlockSource::Manual]);

    $this->mockApi->shouldReceive('listManaged')->once()->andReturn([
        '1.2.3.4' => 'rule1',
        '9.9.9.9' => 'stale-rule',
    ]);
    $this->mockApi->shouldNotReceive('create');
    $this->mockApi->shouldReceive('delete')->once()->with('stale-rule');

    $this->target->reconcile([$a]);
});

it('is a no-op on a second run once state already matches', function () {
    // The idempotency acceptance criterion, exercised directly.
    $a = BlacklistedIp::create(['ip' => '1.2.3.4', 'source' => BlockSource::Manual]);

    $this->mockApi->shouldReceive('listManaged')->once()->andReturn(['1.2.3.4' => 'rule1']);
    $this->mockApi->shouldNotReceive('create');
    $this->mockApi->shouldNotReceive('delete');

    $this->target->reconcile([$a]);
});

it('skips a record with an unsupported CIDR prefix during reconcile instead of aborting', function () {
    $bad = BlacklistedIp::create(['ip' => '203.0.113.0/20', 'source' => BlockSource::Manual]);
    $good = BlacklistedIp::create(['ip' => '1.2.3.4', 'source' => BlockSource::Manual]);

    $this->mockApi->shouldReceive('listManaged')->once()->andReturn([]);
    $this->mockApi->shouldReceive('create')->once()->with('ip', '1.2.3.4');

    $this->target->reconcile([$bad, $good]);
});

it('includes Sync-sourced records during reconcile, unlike LaravelTarget', function () {
    $synced = BlacklistedIp::create(['ip' => '1.2.3.4', 'source' => BlockSource::Sync]);

    $this->mockApi->shouldReceive('listManaged')->once()->andReturn([]);
    $this->mockApi->shouldReceive('create')->once()->with('ip', '1.2.3.4');

    $this->target->reconcile([$synced]);
});

it('keeps creating the rest of the batch when one create fails', function () {
    // Without per-item isolation, one conflicting/foreign rule anywhere in
    // the active set would abort every later create AND the whole delete
    // loop below it for the entire reconcile run.
    config()->set('watchtower.log_channel', 'stack');

    $conflicting = BlacklistedIp::create(['ip' => '1.2.3.4', 'source' => BlockSource::Manual]);
    $fine = BlacklistedIp::create(['ip' => '5.6.7.8', 'source' => BlockSource::Manual]);
    $staleManaged = ['9.9.9.9' => 'stale-rule'];

    $this->mockApi->shouldReceive('listManaged')->once()->andReturn($staleManaged);
    $this->mockApi->shouldReceive('create')->once()->with('ip', '1.2.3.4')->andThrow(new RuntimeException('conflict'));
    $this->mockApi->shouldReceive('create')->once()->with('ip', '5.6.7.8');
    $this->mockApi->shouldReceive('delete')->once()->with('stale-rule');

    Log::shouldReceive('channel')->with('stack')->andReturnSelf();
    Log::shouldReceive('warning')->once()->with(
        Mockery::pattern('/\[cloudflare\] could not reconcile one record/'),
        Mockery::on(fn ($ctx) => $ctx['ip'] === '1.2.3.4' && $ctx['error'] === 'conflict')
    );

    $this->target->reconcile([$conflicting, $fine]);
});

it('keeps deleting the rest of the batch when one delete fails', function () {
    config()->set('watchtower.log_channel', 'stack');

    $this->mockApi->shouldReceive('listManaged')->once()->andReturn([
        '9.9.9.9'  => 'gone-already',
        '9.9.9.10' => 'stale-rule',
    ]);
    $this->mockApi->shouldReceive('delete')->once()->with('gone-already')->andThrow(new RuntimeException('not found'));
    $this->mockApi->shouldReceive('delete')->once()->with('stale-rule');

    Log::shouldReceive('channel')->with('stack')->andReturnSelf();
    Log::shouldReceive('warning')->once()->with(
        Mockery::pattern('/\[cloudflare\] could not reconcile one record/'),
        Mockery::on(fn ($ctx) => $ctx['ip'] === '9.9.9.9' && $ctx['error'] === 'not found')
    );

    $this->target->reconcile([]);
});
