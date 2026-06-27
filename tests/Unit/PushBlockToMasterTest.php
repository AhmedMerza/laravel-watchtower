<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;
use Watchtower\Enums\BlockSource;
use Watchtower\Jobs\PushBlockToMaster;
use Watchtower\Models\BlacklistedIp;

beforeEach(function () {
    config()->set('watchtower.sync.master_url', 'https://master.example.com');
    config()->set('watchtower.sync.secret', 'test-secret');
    config()->set('watchtower.log_channel', 'stack');

    $this->record = BlacklistedIp::create([
        'ip'         => '1.2.3.4',
        'reason'     => 'test',
        'source'     => BlockSource::Manual,
        'source_env' => 'staging',
    ]);
});

it('posts to master with an HMAC signature', function () {
    Http::fake([
        'master.example.com/watchtower/api/block' => Http::response(['ok' => true], 200),
    ]);

    (new PushBlockToMaster($this->record))->handle();

    Http::assertSent(function ($request) {
        return $request->url() === 'https://master.example.com/watchtower/api/block'
            && $request->hasHeader('X-Watchtower-Signature')
            && $request->hasHeader('X-Watchtower-Timestamp')
            && $request['ip'] === '1.2.3.4';
    });
});

it('throws a RuntimeException on non-2xx response so the queue retries', function () {
    Http::fake([
        'master.example.com/watchtower/api/block' => Http::response([], 500),
    ]);

    expect(fn () => (new PushBlockToMaster($this->record))->handle())
        ->toThrow(RuntimeException::class, 'HTTP 500');
});

it('does nothing when master URL is not configured', function () {
    config()->set('watchtower.sync.master_url', null);

    Http::fake();

    (new PushBlockToMaster($this->record))->handle();

    Http::assertNothingSent();
});

it('logs a warning on final failure via failed()', function () {
    Log::shouldReceive('channel')->with('stack')->andReturnSelf();
    Log::shouldReceive('warning')->once()->with(
        'Watchtower: PushBlockToMaster failed',
        Mockery::on(fn ($ctx) => $ctx['ip'] === '1.2.3.4')
    );

    (new PushBlockToMaster($this->record))->failed(new RuntimeException('connection refused'));
});
