<?php

declare(strict_types=1);

use Watchtower\Support\BlockTargetRegistry;
use Watchtower\Targets\LaravelTarget;

it('includes the laravel target when a master URL is configured', function () {
    config()->set('watchtower.sync.master_url', 'https://master.example.com');

    $targets = (new BlockTargetRegistry)->enabled();

    expect($targets)->toHaveKey('laravel')
        ->and($targets['laravel'])->toBeInstanceOf(LaravelTarget::class);
});

it('is empty for a vanilla single-environment install', function () {
    config()->set('watchtower.sync.master_url', null);

    expect((new BlockTargetRegistry)->enabled())->toBe([]);
});
