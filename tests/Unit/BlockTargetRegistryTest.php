<?php

declare(strict_types=1);

use Watchtower\Support\BlockTargetRegistry;
use Watchtower\Targets\CloudflareTarget;
use Watchtower\Targets\LaravelTarget;
use Watchtower\Targets\NginxFileTarget;

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

it('includes the cloudflare target when enabled with both credentials set', function () {
    config()->set('watchtower.block_targets.cloudflare.enabled', true);
    config()->set('watchtower.block_targets.cloudflare.account_id', 'acct123');
    config()->set('watchtower.block_targets.cloudflare.api_token', 'token123');

    $targets = (new BlockTargetRegistry)->enabled();

    expect($targets)->toHaveKey('cloudflare')
        ->and($targets['cloudflare'])->toBeInstanceOf(CloudflareTarget::class);
});

it('excludes cloudflare when enabled but missing the account id', function () {
    config()->set('watchtower.block_targets.cloudflare.enabled', true);
    config()->set('watchtower.block_targets.cloudflare.account_id', null);
    config()->set('watchtower.block_targets.cloudflare.api_token', 'token123');

    expect((new BlockTargetRegistry)->enabled())->not->toHaveKey('cloudflare');
});

it('excludes cloudflare when enabled but missing the api token', function () {
    config()->set('watchtower.block_targets.cloudflare.enabled', true);
    config()->set('watchtower.block_targets.cloudflare.account_id', 'acct123');
    config()->set('watchtower.block_targets.cloudflare.api_token', null);

    expect((new BlockTargetRegistry)->enabled())->not->toHaveKey('cloudflare');
});

it('excludes cloudflare when credentials are set but it is not enabled', function () {
    config()->set('watchtower.block_targets.cloudflare.enabled', false);
    config()->set('watchtower.block_targets.cloudflare.account_id', 'acct123');
    config()->set('watchtower.block_targets.cloudflare.api_token', 'token123');

    expect((new BlockTargetRegistry)->enabled())->not->toHaveKey('cloudflare');
});

it('includes the nginx_file target when enabled with a path set', function () {
    config()->set('watchtower.block_targets.nginx_file.enabled', true);
    config()->set('watchtower.block_targets.nginx_file.path', '/tmp/watchtower-deny.conf');

    $targets = (new BlockTargetRegistry)->enabled();

    expect($targets)->toHaveKey('nginx_file')
        ->and($targets['nginx_file'])->toBeInstanceOf(NginxFileTarget::class);
});

it('includes nginx_file even with no reload_command configured', function () {
    config()->set('watchtower.block_targets.nginx_file.enabled', true);
    config()->set('watchtower.block_targets.nginx_file.path', '/tmp/watchtower-deny.conf');
    config()->set('watchtower.block_targets.nginx_file.reload_command', null);

    expect((new BlockTargetRegistry)->enabled())->toHaveKey('nginx_file');
});

it('excludes nginx_file when enabled but missing a path', function () {
    config()->set('watchtower.block_targets.nginx_file.enabled', true);
    config()->set('watchtower.block_targets.nginx_file.path', null);

    expect((new BlockTargetRegistry)->enabled())->not->toHaveKey('nginx_file');
});

it('excludes nginx_file when a path is set but it is not enabled', function () {
    config()->set('watchtower.block_targets.nginx_file.enabled', false);
    config()->set('watchtower.block_targets.nginx_file.path', '/tmp/watchtower-deny.conf');

    expect((new BlockTargetRegistry)->enabled())->not->toHaveKey('nginx_file');
});
