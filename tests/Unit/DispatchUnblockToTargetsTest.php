<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Log;
use Watchtower\Events\IpUnblocked;
use Watchtower\Listeners\DispatchUnblockToTargets;
use Watchtower\Targets\LaravelTarget;

it('calls remove on every enabled target', function () {
    config()->set('watchtower.sync.master_url', 'https://master.example.com');

    $mock = Mockery::mock(LaravelTarget::class);
    $mock->shouldReceive('remove')->once()->with('1.2.3.4');
    app()->instance(LaravelTarget::class, $mock);

    app(DispatchUnblockToTargets::class)->handle(new IpUnblocked('1.2.3.4'));
});

it('catches a target that throws and logs instead of propagating', function () {
    config()->set('watchtower.log_channel', 'stack');
    config()->set('watchtower.sync.master_url', 'https://master.example.com');

    $mock = Mockery::mock(LaravelTarget::class);
    $mock->shouldReceive('remove')->once()->andThrow(new RuntimeException('boom'));
    app()->instance(LaravelTarget::class, $mock);

    Log::shouldReceive('channel')->with('stack')->andReturnSelf();
    Log::shouldReceive('warning')->once()->with(
        Mockery::pattern('/\[laravel\] failed to remove/'),
        Mockery::on(fn ($ctx) => $ctx['ip'] === '1.2.3.4' && $ctx['error'] === 'boom')
    );

    expect(fn () => app(DispatchUnblockToTargets::class)->handle(new IpUnblocked('1.2.3.4')))
        ->not->toThrow(RuntimeException::class);
});
