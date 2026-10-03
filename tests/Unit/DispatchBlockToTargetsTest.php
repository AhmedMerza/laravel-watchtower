<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Queue;
use Watchtower\Enums\BlockSource;
use Watchtower\Events\IpBlocked;
use Watchtower\Jobs\PushBlockToMaster;
use Watchtower\Listeners\DispatchBlockToTargets;
use Watchtower\Models\BlacklistedIp;
use Watchtower\Support\BlockScope;
use Watchtower\Targets\LaravelTarget;

it('applies to the enabled target for a GLOBAL-scope block', function () {
    Queue::fake();
    config()->set('watchtower.sync.master_url', 'https://master.example.com');

    $record = BlacklistedIp::create(['ip' => '1.2.3.4', 'scope' => BlockScope::GLOBAL, 'source' => BlockSource::Manual]);

    app(DispatchBlockToTargets::class)->handle(new IpBlocked($record));

    Queue::assertPushed(PushBlockToMaster::class);
});

it('does not touch any target for a scoped block', function () {
    Queue::fake();
    config()->set('watchtower.scopes', ['auth']);
    config()->set('watchtower.sync.master_url', 'https://master.example.com');

    // An edge/infrastructure target has no route to enforce "only these
    // paths" against — this is the central guard #38 taught this repo to
    // keep in one place rather than inside every target.
    $record = BlacklistedIp::create(['ip' => '1.2.3.4', 'scope' => 'auth', 'source' => BlockSource::Manual]);

    app(DispatchBlockToTargets::class)->handle(new IpBlocked($record));

    Queue::assertNotPushed(PushBlockToMaster::class);
});

it('catches a target that throws and logs instead of propagating', function () {
    // Only one target exists in this PR, so this proves the catch doesn't
    // let the exception escape and that it's logged with the target's name.
    // Proof that a SECOND target still runs when this one throws lands with
    // PR2's cloudflare target.
    config()->set('watchtower.log_channel', 'stack');
    config()->set('watchtower.sync.master_url', 'https://master.example.com');

    $mock = Mockery::mock(LaravelTarget::class);
    $mock->shouldReceive('apply')->once()->andThrow(new RuntimeException('boom'));
    app()->instance(LaravelTarget::class, $mock);

    $record = BlacklistedIp::create(['ip' => '1.2.3.4', 'scope' => BlockScope::GLOBAL, 'source' => BlockSource::Manual]);

    Log::shouldReceive('channel')->with('stack')->andReturnSelf();
    Log::shouldReceive('warning')->once()->with(
        Mockery::pattern('/\[laravel\] failed to apply/'),
        Mockery::on(fn ($ctx) => $ctx['ip'] === '1.2.3.4' && $ctx['error'] === 'boom')
    );

    expect(fn () => app(DispatchBlockToTargets::class)->handle(new IpBlocked($record)))
        ->not->toThrow(RuntimeException::class);
});
