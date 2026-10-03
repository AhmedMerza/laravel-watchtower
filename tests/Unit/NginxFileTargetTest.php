<?php

declare(strict_types=1);

use Watchtower\Enums\BlockSource;
use Watchtower\Models\BlacklistedIp;
use Watchtower\Support\NginxDenyFile;
use Watchtower\Targets\NginxFileTarget;

beforeEach(function () {
    $this->mockFile = Mockery::mock(NginxDenyFile::class);
    $this->target = new NginxFileTarget($this->mockFile);
});

it('adds the record ip on apply', function () {
    $record = BlacklistedIp::create(['ip' => '1.2.3.4', 'source' => BlockSource::Manual]);

    $this->mockFile->shouldReceive('add')->once()->with('1.2.3.4');

    $this->target->apply($record);
});

it('applies to a Sync-sourced record, unlike LaravelTarget', function () {
    // The anti-loop skip on LaravelTarget is specific to the master/satellite
    // echo risk; nginx_file has no such risk, so a Sync-sourced global block
    // must still be written.
    $record = BlacklistedIp::create(['ip' => '1.2.3.4', 'source' => BlockSource::Sync]);

    $this->mockFile->shouldReceive('add')->once()->with('1.2.3.4');

    $this->target->apply($record);
});

it('removes the ip on remove', function () {
    $this->mockFile->shouldReceive('remove')->once()->with('1.2.3.4');

    $this->target->remove('1.2.3.4');
});

it('replaces the whole set with every active record ip on reconcile', function () {
    $a = BlacklistedIp::create(['ip' => '1.2.3.4', 'source' => BlockSource::Manual]);
    $b = BlacklistedIp::create(['ip' => '5.6.7.8', 'source' => BlockSource::Sync]);

    $this->mockFile->shouldReceive('replaceAll')->once()->with(['1.2.3.4', '5.6.7.8']);

    $this->target->reconcile([$a, $b]);
});

it('passes an empty set through to replaceAll when nothing is active', function () {
    $this->mockFile->shouldReceive('replaceAll')->once()->with([]);

    $this->target->reconcile([]);
});
