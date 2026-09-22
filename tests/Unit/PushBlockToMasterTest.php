<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;
use Watchtower\Enums\BlockSource;
use Watchtower\Jobs\PushBlockToMaster;
use Watchtower\Models\BlacklistedIp;
use Watchtower\Support\SyncSignature;

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
        'master.example.com/watchtower/sync/block' => Http::response(['ok' => true], 200),
    ]);

    (new PushBlockToMaster($this->record))->handle();

    Http::assertSent(function ($request) {
        return $request->url() === 'https://master.example.com/watchtower/sync/block'
            && $request->hasHeader('X-Watchtower-Signature')
            && $request->hasHeader('X-Watchtower-Timestamp')
            && $request['ip'] === '1.2.3.4';
    });
});

it('throws a RuntimeException on non-2xx response so the queue retries', function () {
    Http::fake([
        'master.example.com/watchtower/sync/block' => Http::response([], 500),
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

it('does not push a block that arrived by sync', function () {
    // A master whose own master_url points at itself would otherwise push
    // every incoming block straight back to itself, forever.
    $this->record->update(['source' => BlockSource::Sync]);

    Http::fake();

    (new PushBlockToMaster($this->record))->handle();

    Http::assertNothingSent();
});

it('does not push unsigned when the secret is missing', function () {
    config()->set('watchtower.sync.secret', null);

    Log::shouldReceive('channel')->with('stack')->andReturnSelf();
    Log::shouldReceive('warning')->once()->with(
        Mockery::pattern('/WATCHTOWER_SYNC_SECRET/'),
        Mockery::on(fn ($ctx) => $ctx['ip'] === '1.2.3.4')
    );

    Http::fake();

    (new PushBlockToMaster($this->record))->handle();

    Http::assertNothingSent();
});

it('signs the exact bytes it sends', function () {
    Http::fake([
        'master.example.com/watchtower/sync/block' => Http::response(['ok' => true], 200),
    ]);

    (new PushBlockToMaster($this->record))->handle();

    Http::assertSent(function ($request) {
        $expected = SyncSignature::compute(
            $request->header('X-Watchtower-Timestamp')[0],
            'POST',
            SyncSignature::PUSH_PATH,
            $request->body(),
            'test-secret'
        );

        return hash_equals($expected, $request->header('X-Watchtower-Signature')[0]);
    });
});

it('logs a warning on final failure via failed()', function () {
    Log::shouldReceive('channel')->with('stack')->andReturnSelf();
    Log::shouldReceive('warning')->once()->with(
        'Watchtower: PushBlockToMaster failed',
        Mockery::on(fn ($ctx) => $ctx['ip'] === '1.2.3.4')
    );

    (new PushBlockToMaster($this->record))->failed(new RuntimeException('connection refused'));
});

/*
|--------------------------------------------------------------------------
| The outbound half of #56.
|--------------------------------------------------------------------------
|
| The master's never_auto_block decision is only as good as this field. The
| receiving side had tests from the start; the SENDING side had none, so
| deleting this one array entry left all 583 tests green — the producer was
| never asserted, only the consumer.
*/

it('tells the master that a rule made this block', function () {
    Http::fake(['master.example.com/watchtower/sync/block' => Http::response(['ok' => true], 200)]);

    $auto = BlacklistedIp::create([
        'ip'         => '9.8.7.6',
        'reason'     => 'Brute force',
        'source'     => BlockSource::Auto,
        'source_env' => 'staging',
    ]);

    (new PushBlockToMaster($auto))->handle();

    Http::assertSent(fn ($request): bool => $request['source'] === 'auto');
});

it('tells the master that an admin made this block', function () {
    // The other half of the same guarantee: the master must be able to tell
    // these apart, or never_auto_block either refuses everything or nothing.
    Http::fake(['master.example.com/watchtower/sync/block' => Http::response(['ok' => true], 200)]);

    (new PushBlockToMaster($this->record))->handle();

    Http::assertSent(fn ($request): bool => $request['source'] === 'manual');
});
