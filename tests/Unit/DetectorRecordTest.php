<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Queue;
use Watchtower\Enums\BlockSource;
use Watchtower\Models\BlacklistedIp;
use Watchtower\Services\AutoBlockService;
use Watchtower\Services\BlacklistCache;
use Watchtower\Services\BlacklistService;
use Watchtower\Services\OffenceLedger;
use Watchtower\Support\HitWindow;

beforeEach(function () {
    config()->set('cache.default', 'array');
    config()->set('watchtower.cache.store', 'array');
    Cache::flush();

    Event::fake();
    Queue::fake();

    config()->set('watchtower.auto_block.enabled', true);
    config()->set('watchtower.auto_block.block_duration_minutes', 60);
    // Armed: these cases are about thresholds and guards, not about the
    // shipped default, which has its own test below.
    config()->set('watchtower.auto_block.mode', 'block');
    config()->set('watchtower.auto_block.detectors.failed_logins', [
        'enabled'        => true,
        'count'          => 3,
        'window_minutes' => 5,
    ]);

    $this->hits = new HitWindow;
    $this->service = new AutoBlockService(
        new BlacklistService(new BlacklistCache),
        $this->hits,
        new OffenceLedger,
    );
});

it('ships every detector switched off, with a usable starting threshold', function () {
    // Read the shipped file rather than the merged config, so this can't be
    // satisfied by a test override.
    $shipped = require __DIR__.'/../../config/watchtower.php';

    expect($shipped['auto_block']['detectors'])->not->toBeEmpty();

    foreach ($shipped['auto_block']['detectors'] as $name => $settings) {
        expect($settings['enabled'])->toBeFalse("detector '{$name}' ships enabled")
            ->and($settings['count'])->toBeInt()->toBeGreaterThan(0)
            ->and($settings['window_minutes'])->toBeInt()->toBeGreaterThan(0);
    }
});

it('does not block until the threshold is reached', function () {
    expect($this->service->record('failed_logins', '198.51.100.1'))->toBeFalse()
        ->and($this->service->record('failed_logins', '198.51.100.1'))->toBeFalse();

    $this->assertDatabaseMissing('blacklisted_ips', ['ip' => '198.51.100.1']);

    expect($this->service->record('failed_logins', '198.51.100.1'))->toBeTrue();

    $this->assertDatabaseHas('blacklisted_ips', [
        'ip'     => '198.51.100.1',
        'source' => BlockSource::Auto->value,
    ]);
});

it('does nothing when auto-block is switched off entirely', function () {
    config()->set('watchtower.auto_block.enabled', false);

    foreach (range(1, 5) as $i) {
        expect($this->service->record('failed_logins', '198.51.100.2'))->toBeFalse();
    }

    $this->assertDatabaseMissing('blacklisted_ips', ['ip' => '198.51.100.2']);
});

it('does nothing for a detector that is not enabled', function () {
    config()->set('watchtower.auto_block.detectors.failed_logins.enabled', false);

    foreach (range(1, 5) as $i) {
        expect($this->service->record('failed_logins', '198.51.100.3'))->toBeFalse();
    }

    $this->assertDatabaseMissing('blacklisted_ips', ['ip' => '198.51.100.3']);
});

it('does nothing for a detector name that has no configuration', function () {
    foreach (range(1, 5) as $i) {
        expect($this->service->record('not_a_detector', '198.51.100.12'))->toBeFalse();
    }

    $this->assertDatabaseMissing('blacklisted_ips', ['ip' => '198.51.100.12']);
});

it('counts each address separately', function () {
    $this->service->record('failed_logins', '198.51.100.5');
    $this->service->record('failed_logins', '198.51.100.5');
    $this->service->record('failed_logins', '198.51.100.6');

    $this->assertDatabaseMissing('blacklisted_ips', ['ip' => '198.51.100.5']);
    $this->assertDatabaseMissing('blacklisted_ips', ['ip' => '198.51.100.6']);
});

it('warns instead of blocking when enough signed-in users share the address', function () {
    config()->set('watchtower.auto_block.shared_ip_user_threshold', 3);

    $logChannel = Mockery::mock()->shouldIgnoreMissing();
    $logChannel->shouldReceive('warning')
        ->once()
        ->withArgs(function (string $message, array $context): bool {
            return $context['would_have_blocked'] === true
                && $context['detector'] === 'failed_logins'
                && $context['not_blocked_because'] === 'shared IP'
                && $context['distinct_users'] === 3
                && $context['user_ids'] === ['7', '8', '9'];
        });
    Log::shouldReceive('channel')->andReturn($logChannel);

    foreach ([7, 8, 9] as $userId) {
        $this->service->record('failed_logins', '198.51.100.7', $userId);
    }

    $this->assertDatabaseMissing('blacklisted_ips', ['ip' => '198.51.100.7']);
});

it('still blocks when the same volume comes from one signed-in user', function () {
    config()->set('watchtower.auto_block.shared_ip_user_threshold', 3);

    foreach (range(1, 3) as $i) {
        $this->service->record('failed_logins', '198.51.100.8', 42);
    }

    // One person making three attempts is one distinct user, however many
    // times they are counted.
    $this->assertDatabaseHas('blacklisted_ips', ['ip' => '198.51.100.8']);
});

it('reports an address that is already blocked without counting it again', function () {
    BlacklistedIp::create([
        'ip'         => '198.51.100.9',
        'source'     => BlockSource::Manual,
        'source_env' => 'testing',
    ]);
    app(BlacklistCache::class)->rebuild();

    expect($this->service->record('failed_logins', '198.51.100.9'))->toBeTrue();

    // No counter was started for it, so nothing is carried into the window
    // that follows the block lapsing.
    expect($this->hits->users('failed_logins', '198.51.100.9'))->toBe([]);
});

it('clears the counter once it has blocked, so a lapsed block does not re-fire instantly', function () {
    foreach (range(1, 3) as $i) {
        $this->service->record('failed_logins', '198.51.100.10');
    }

    $this->assertDatabaseHas('blacklisted_ips', ['ip' => '198.51.100.10']);

    app(BlacklistService::class)->unblock('198.51.100.10');
    BlacklistedIp::query()->delete();
    app(BlacklistCache::class)->rebuild();

    // The counter was reset by the block, so this is hit 1 of 3, not 4.
    expect($this->service->record('failed_logins', '198.51.100.10'))->toBeFalse();
});

it('lets a detector override the global mode', function () {
    config()->set('watchtower.auto_block.mode', 'block');
    config()->set('watchtower.auto_block.detectors.failed_logins.mode', 'disabled');

    foreach (range(1, 5) as $i) {
        expect($this->service->record('failed_logins', '198.51.100.11'))->toBeFalse();
    }

    $this->assertDatabaseMissing('blacklisted_ips', ['ip' => '198.51.100.11']);
});

it('holds back an address in never_auto_block and says so', function () {
    config()->set('watchtower.never_auto_block', ['198.51.100.13']);

    $logChannel = Mockery::mock()->shouldIgnoreMissing();
    $logChannel->shouldReceive('warning')
        ->once()
        ->withArgs(fn (string $message, array $context): bool => $context['not_blocked_because'] === 'never_auto_block'
            && $context['detector'] === 'failed_logins');
    Log::shouldReceive('channel')->andReturn($logChannel);

    foreach (range(1, 3) as $i) {
        expect($this->service->record('failed_logins', '198.51.100.13'))->toBeFalse();
    }

    $this->assertDatabaseMissing('blacklisted_ips', ['ip' => '198.51.100.13']);
});

it('counts an IPv6 client by the network a block would cover, not the address it hops to', function () {
    // Three different addresses inside one /64. A counter keyed on the bare
    // address would see a single hit for each and never reach the threshold,
    // handing an IPv6 attacker a fresh budget per hop — inside the very
    // prefix a block would have covered anyway.
    foreach (['2001:db8:1:2::1', '2001:db8:1:2::2', '2001:db8:1:2::3'] as $ip) {
        $this->service->record('failed_logins', $ip);
    }

    $this->assertDatabaseHas('blacklisted_ips', ['ip' => '2001:db8:1:2::/64']);
});

it('keeps separate counters for addresses in different IPv6 networks', function () {
    foreach (['2001:db8:1:2::1', '2001:db8:9:9::1', '2001:db8:7:7::1'] as $ip) {
        expect($this->service->record('failed_logins', $ip))->toBeFalse();
    }

    expect(BlacklistedIp::count())->toBe(0);
});

it('lets the window decay, so hits do not accumulate forever', function () {
    config()->set('watchtower.auto_block.detectors.failed_logins.window_minutes', 5);

    // Two hits, then past the window, then two more. Without decay that is
    // four hits against a threshold of three and the address is blocked.
    $this->service->record('failed_logins', '198.51.100.20');
    $this->service->record('failed_logins', '198.51.100.20');

    $this->travel(6)->minutes();

    expect($this->service->record('failed_logins', '198.51.100.20'))->toBeFalse()
        ->and($this->service->record('failed_logins', '198.51.100.20'))->toBeFalse();

    $this->assertDatabaseMissing('blacklisted_ips', ['ip' => '198.51.100.20']);
});

it('does not carry a previous window\'s users into the next one', function () {
    config()->set('watchtower.auto_block.shared_ip_user_threshold', 3);
    config()->set('watchtower.auto_block.detectors.failed_logins.window_minutes', 5);

    // Two users seen late in one window. Their set must expire with the
    // window that opened it — if its TTL slid forward on each new user it
    // would outlive the counter, and these two would be counted again
    // alongside a third in the next window, standing down a block that
    // only one person's traffic actually earned.
    $this->hits->recordUser('failed_logins', '198.51.100.21', 1, 300);
    $this->hits->recordUser('failed_logins', '198.51.100.21', 2, 300);

    expect($this->hits->users('failed_logins', '198.51.100.21'))->toBe(['1', '2']);

    $this->travel(6)->minutes();

    expect($this->hits->users('failed_logins', '198.51.100.21'))->toBe([]);
});
