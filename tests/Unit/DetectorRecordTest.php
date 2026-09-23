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

it('re-measures a shared address instead of holding the verdict', function () {
    config()->set('watchtower.auto_block.shared_ip_user_threshold', 3);

    $logChannel = Mockery::mock()->shouldIgnoreMissing();
    // Twice, not once. A detector holds a decision it was stopped from
    // enforcing for as long as the block would have run, so a dry run reports
    // one entry per block it predicts — but `warn` mode and never_auto_block
    // are settings that will say the same thing in an hour, and the number of
    // signed-in users an address is showing is not. Holding this one would
    // turn a guard an attacker has to keep re-earning into an hour of
    // immunity bought once.
    $logChannel->shouldReceive('warning')
        ->twice()
        ->withArgs(fn (string $m, array $c): bool => ($c['not_blocked_because'] ?? null) === 'shared IP');
    Log::shouldReceive('channel')->andReturn($logChannel);

    foreach ([7, 8, 9, 7, 8, 9] as $userId) {
        $this->service->record('failed_logins', '198.51.100.11', $userId);
    }

    $this->assertDatabaseMissing('blacklisted_ips', ['ip' => '198.51.100.11']);
});

it('blocks a formerly-shared address as soon as its users stop appearing', function () {
    config()->set('watchtower.auto_block.shared_ip_user_threshold', 3);
    Log::shouldReceive('channel')->andReturn(Mockery::mock()->shouldIgnoreMissing());

    foreach ([7, 8, 9] as $userId) {
        $this->service->record('failed_logins', '198.51.100.12', $userId);
    }

    $this->assertDatabaseMissing('blacklisted_ips', ['ip' => '198.51.100.12']);

    // The same address, now anonymous. Holding the shared-IP verdict the way
    // a warn-mode one is held would have left this address untouchable for
    // block_duration_minutes on the strength of three accounts that showed up
    // once — which is the attack the README says this guard does not stop.
    // Re-measuring blocks it on the very next crossing.
    foreach (range(1, 3) as $i) {
        $this->service->record('failed_logins', '198.51.100.12');
    }

    $this->assertDatabaseHas('blacklisted_ips', ['ip' => '198.51.100.12']);
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

it('does not let an exempt address shield the rest of its IPv6 prefix', function () {
    config()->set('watchtower.never_auto_block', ['2001:db8:1:2::9']);
    Log::shouldReceive('channel')->andReturn(Mockery::mock()->shouldIgnoreMissing());

    // The exempt address trips the detector and is refused. The refusal
    // opens a hold keyed on the /64 a block would have covered — the same
    // key the counter uses.
    foreach (range(1, 3) as $i) {
        $this->service->record('failed_logins', '2001:db8:1:2::9');
    }

    expect(BlacklistedIp::count())->toBe(0);

    // Another address in that prefix is on no list. The refusal was about
    // ONE address — BlacklistService::block() checks it before the target
    // is widened — so the hold must not answer for this one. Served raw, it
    // would leave the whole /64 uncounted, unevaluated and unblocked.
    foreach (range(1, 3) as $i) {
        $this->service->record('failed_logins', '2001:db8:1:2::666');
    }

    $this->assertDatabaseHas('blacklisted_ips', ['ip' => '2001:db8:1:2::/64']);
});

it('blocks a taken-off-the-list address on its next crossing, not when the old hold lapses', function () {
    config()->set('watchtower.never_auto_block', ['198.51.100.23']);
    Log::shouldReceive('channel')->andReturn(Mockery::mock()->shouldIgnoreMissing());

    foreach (range(1, 3) as $i) {
        $this->service->record('failed_logins', '198.51.100.23');
    }

    $this->assertDatabaseMissing('blacklisted_ips', ['ip' => '198.51.100.23']);

    // The hold from the refusal is still live, but it stored WHY it was
    // opened — and a never_* reason is re-asked of the list, which no
    // longer names this address.
    config()->set('watchtower.never_auto_block', []);

    foreach (range(1, 3) as $i) {
        $this->service->record('failed_logins', '198.51.100.23');
    }

    $this->assertDatabaseHas('blacklisted_ips', ['ip' => '198.51.100.23']);
});

it('holds a dry-run decision for every address in the prefix a block would have covered', function () {
    config()->set('watchtower.auto_block.mode', 'warn');

    $logChannel = Mockery::mock()->shouldIgnoreMissing();
    // Once, though two different addresses cross. The hold is keyed on the
    // /64, the same target the counter and the block use, so the second
    // address reads what the first one wrote. A read keyed on the bare
    // address would miss it and report again.
    $logChannel->shouldReceive('warning')
        ->once()
        ->withArgs(fn (string $m, array $c): bool => ($c['not_blocked_because'] ?? null) === 'warn mode');
    Log::shouldReceive('channel')->andReturn($logChannel);

    foreach (range(1, 3) as $i) {
        $this->service->record('failed_logins', '2001:db8:1:2::1');
    }

    foreach (range(1, 3) as $i) {
        $this->service->record('failed_logins', '2001:db8:1:2::2');
    }

    $this->assertDatabaseMissing('blacklisted_ips', ['ip' => '2001:db8:1:2::/64']);
});

it('holds a never_block address after one refusal', function () {
    config()->set('watchtower.never_block', ['198.51.100.22']);

    $logChannel = Mockery::mock()->shouldIgnoreMissing();
    // The refusal itself is a debug line, not a would-have-blocked warning.
    // What the hold buys is paying it once rather than once per crossing —
    // never_block is as standing a refusal as never_auto_block, whose hold
    // has its own test.
    $logChannel->shouldReceive('debug')
        ->once()
        ->withArgs(fn (string $m, array $c): bool => ($c['ip'] ?? null) === '198.51.100.22');
    Log::shouldReceive('channel')->andReturn($logChannel);

    foreach (range(1, 9) as $i) {
        expect($this->service->record('failed_logins', '198.51.100.22'))->toBeFalse();
    }

    $this->assertDatabaseMissing('blacklisted_ips', ['ip' => '198.51.100.22']);
});

it('holds a scoped detector\'s dry-run decision once per block it predicts', function () {
    config()->set('watchtower.scopes', ['auth']);
    config()->set('watchtower.auto_block.detectors.failed_logins.mode', 'warn');
    config()->set('watchtower.auto_block.detectors.failed_logins.scope', 'auth');

    $logChannel = Mockery::mock()->shouldIgnoreMissing();
    $logChannel->shouldReceive('warning')
        ->once()
        ->withArgs(fn (string $m, array $c): bool => ($c['not_blocked_because'] ?? null) === 'warn mode');
    Log::shouldReceive('channel')->andReturn($logChannel);

    // A scoped detector never returns true — the route middleware carrying
    // the scope is what enforces a scoped block — but the hold works the
    // same: one report, then silence for the span the block would have run.
    foreach (range(1, 6) as $i) {
        expect($this->service->record('failed_logins', '198.51.100.26'))->toBeFalse();
    }

    $this->assertDatabaseMissing('blacklisted_ips', ['ip' => '198.51.100.26']);
});

it('treats a zero block duration as one minute, never as forever', function () {
    config()->set('watchtower.auto_block.mode', 'warn');
    config()->set('watchtower.auto_block.block_duration_minutes', 0);

    $logChannel = Mockery::mock()->shouldIgnoreMissing();
    // Twice: once now, once after the minute the duration clamps up to. A
    // literal 0 means "no expiry" on some cache drivers, which would hold
    // the decision — and silence the dry run — permanently.
    $logChannel->shouldReceive('warning')
        ->twice()
        ->withArgs(fn (string $m, array $c): bool => ($c['not_blocked_because'] ?? null) === 'warn mode');
    Log::shouldReceive('channel')->andReturn($logChannel);

    foreach (range(1, 3) as $i) {
        $this->service->record('failed_logins', '198.51.100.24');
    }

    // Inside the clamped minute the hold still answers.
    $this->travel(30)->seconds();

    foreach (range(1, 3) as $i) {
        $this->service->record('failed_logins', '198.51.100.24');
    }

    // Past it, the address is re-decided and reported again.
    $this->travel(31)->seconds();

    foreach (range(1, 3) as $i) {
        $this->service->record('failed_logins', '198.51.100.24');
    }
});

it('opens a hold for at least a second even when asked for none', function () {
    // The service clamps its duration already; this is the same guard at
    // the storage end, where 0 means "forever" on some drivers.
    $this->hits->openNotionalBlock('failed_logins', '198.51.100.25', 'warn', 'warn mode', 0);

    expect($this->hits->notionalHold('failed_logins', '198.51.100.25'))
        ->toBe(['mode' => 'warn', 'reason' => 'warn mode']);
});

it('re-decides a hold left by a version that stored the bare mode', function () {
    config()->set('watchtower.auto_block.mode', 'warn');

    // The pre-reason value shape, as a deploy onto a live cache would find
    // it: a bare mode string at the same key. If the guard in notionalHold()
    // regressed and this flowed through, the array access on it would throw
    // into record()'s fail-open — silently disabling detection for the
    // address until the key lapsed.
    Cache::put('watchtower:blacklist:notional:failed_logins:198.51.100.27', 'warn', 3600);

    $logChannel = Mockery::mock()->shouldIgnoreMissing();
    // Read as "no hold", so the address is re-decided — and that decision
    // rewrites the key with the reason filled in.
    $logChannel->shouldReceive('warning')
        ->once()
        ->withArgs(fn (string $m, array $c): bool => ($c['not_blocked_because'] ?? null) === 'warn mode');
    Log::shouldReceive('channel')->andReturn($logChannel);

    foreach (range(1, 3) as $i) {
        $this->service->record('failed_logins', '198.51.100.27');
    }

    expect($this->hits->notionalHold('failed_logins', '198.51.100.27'))
        ->toBe(['mode' => 'warn', 'reason' => 'warn mode']);
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
