<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Queue;
use Watchtower\Services\AutoBlockService;
use Watchtower\Services\BlacklistCache;
use Watchtower\Services\BlacklistService;
use Watchtower\Support\BlockScope;
use Watchtower\Support\HitWindow;

// logEntry() is defined in AutoBlockServiceTest.php, which Pest loads for this
// directory too.

beforeEach(function () {
    config()->set('cache.default', 'array');
    config()->set('watchtower.cache.store', 'array');
    Cache::flush();

    Event::fake();
    Queue::fake();

    config()->set('watchtower.auto_block.enabled', true);
    config()->set('watchtower.auto_block.mode', 'block');
    config()->set('watchtower.auto_block.block_duration_minutes', 60);
    config()->set('watchtower.auto_block.shared_ip_user_threshold', 3);
    config()->set('watchtower.scopes', ['auth']);

    $this->cache = new BlacklistCache;
    $this->blacklist = new BlacklistService($this->cache);
    $this->service = new AutoBlockService($this->blacklist, new HitWindow);
});

function scopedRule(?string $scope, string $mode = 'block'): void
{
    config()->set('watchtower.auto_block.rules', [array_filter([
        'level'            => 'error',
        'message_contains' => null,
        'count'            => 3,
        'window_minutes'   => 5,
        'mode'             => $mode,
        'scope'            => $scope,
    ], fn ($value) => $value !== null)]);
}

function sharedAddress(string $ip): void
{
    foreach ([1, 2, 3] as $userId) {
        logEntry($ip, ['user_id' => $userId]);
    }
}

it('blocks a shared address in the scope instead of only warning', function () {
    scopedRule('auth');
    sharedAddress('20.20.20.20');

    $this->service->run();

    // The whole point of #27: the attacker on that carrier gateway loses the
    // auth routes, and the 200 other people behind it keep the rest of the app.
    $this->assertDatabaseHas('blacklisted_ips', [
        'ip'     => '20.20.20.20',
        'scope'  => 'auth',
        'source' => 'auto',
    ]);
});

it('logs a scoped downgrade as a real block, not a would-have-blocked', function () {
    scopedRule('auth');
    sharedAddress('20.20.20.21');

    $logChannel = Mockery::mock();
    $logChannel->shouldReceive('warning')
        ->once()
        // `would_have_blocked` stays the canonical filter for things that did
        // NOT happen. This one did, so an operator filtering on it must not
        // find a real block hiding among the near misses.
        ->withArgs(fn (string $message, array $context): bool => $context['downgraded_to_scope'] === 'auth'
            && ! array_key_exists('would_have_blocked', $context));
    $logChannel->shouldReceive('debug')->zeroOrMoreTimes();
    Log::shouldReceive('channel')->andReturn($logChannel);

    $this->service->run();
});

it('still only warns for a shared address when the rule has no scope', function () {
    scopedRule(null);
    sharedAddress('20.20.20.22');

    $this->service->run();

    $this->assertDatabaseMissing('blacklisted_ips', ['ip' => '20.20.20.22']);
});

it('still only warns in warn mode, even with a scope', function () {
    // warn mode is a dry run and has to stay one. If a scope re-armed it,
    // configuring a rule to report would start blocking instead.
    scopedRule('auth', 'warn');
    sharedAddress('20.20.20.23');

    $this->service->run();

    $this->assertDatabaseMissing('blacklisted_ips', ['ip' => '20.20.20.23']);
});

it('still refuses a never_auto_block address, scope or not', function () {
    // never_auto_block is a refusal about an address, not a decision about
    // reach. A scope must not turn it into a downgrade.
    config()->set('watchtower.never_auto_block', ['20.20.20.24']);
    scopedRule('auth');
    sharedAddress('20.20.20.24');

    $this->service->run();

    $this->assertDatabaseMissing('blacklisted_ips', ['ip' => '20.20.20.24']);
});

it('blocks globally when the address is not shared, even on a scoped rule', function () {
    scopedRule('auth');

    // One signed-in user, so the shared-IP guard never fires — the rule
    // blocks in its own scope, which is what it asked for.
    foreach (range(1, 3) as $i) {
        logEntry('20.20.20.25', ['user_id' => 7]);
    }

    $this->service->run();

    $this->assertDatabaseHas('blacklisted_ips', ['ip' => '20.20.20.25', 'scope' => 'auth']);
});

it('blocks nothing and says so when a rule names a scope that is not declared', function () {
    scopedRule('atuh');
    sharedAddress('20.20.20.26');

    $logChannel = Mockery::mock();
    $logChannel->shouldReceive('warning')
        ->once()
        ->withArgs(fn (string $message, array $context): bool => str_contains($message, 'scope is not declared'));
    $logChannel->shouldReceive('debug')->zeroOrMoreTimes();
    Log::shouldReceive('channel')->andReturn($logChannel);

    $this->service->run();

    // Not blocked globally either: treating a typo as the global scope would
    // block the whole app when someone asked for a handful of routes.
    $this->assertDatabaseMissing('blacklisted_ips', ['ip' => '20.20.20.26']);
});

it('records a detector block in the detector scope', function () {
    config()->set('watchtower.auto_block.detectors.failed_logins', [
        'enabled'        => true,
        'count'          => 2,
        'window_minutes' => 5,
        'scope'          => 'auth',
    ]);

    $this->service->record('failed_logins', '20.20.20.27');
    $this->service->record('failed_logins', '20.20.20.27');

    $this->assertDatabaseHas('blacklisted_ips', [
        'ip'     => '20.20.20.27',
        'scope'  => 'auth',
        'source' => 'auto',
    ]);
});

it('records a detector block globally when it names no scope', function () {
    config()->set('watchtower.auto_block.detectors.failed_logins', [
        'enabled'        => true,
        'count'          => 2,
        'window_minutes' => 5,
    ]);

    $this->service->record('failed_logins', '20.20.20.28');
    $this->service->record('failed_logins', '20.20.20.28');

    $this->assertDatabaseHas('blacklisted_ips', [
        'ip'    => '20.20.20.28',
        'scope' => BlockScope::GLOBAL,
    ]);
});
