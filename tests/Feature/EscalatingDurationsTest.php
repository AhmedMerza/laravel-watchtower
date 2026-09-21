<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Queue;
use Watchtower\Models\BlacklistedIp;
use Watchtower\Models\IpOffence;
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
    config()->set('watchtower.auto_block.mode', 'block');
    config()->set('watchtower.auto_block.block_duration_minutes', 60);
    config()->set('watchtower.auto_block.shared_ip_user_threshold', 3);

    config()->set('watchtower.auto_block.escalation.enabled', true);
    config()->set('watchtower.auto_block.escalation.repeat_durations', [360, 1440]);
    config()->set('watchtower.auto_block.escalation.decay_days', 30);

    config()->set('watchtower.auto_block.rules', [[
        'level'          => 'error',
        'count'          => 3,
        'window_minutes' => 5,
    ]]);

    $this->cache = new BlacklistCache;
    $this->blacklist = new BlacklistService($this->cache);
    $this->service = new AutoBlockService($this->blacklist, new HitWindow, new OffenceLedger);
});

/**
 * How many minutes the block on this address is set to last, or null when
 * there is no block. Rounded, because the expiry is computed a few
 * microseconds before it is read.
 */
function blockMinutes(string $ip, string $scope = ''): ?int
{
    $block = BlacklistedIp::where('ip', $ip)->where('scope', $scope)->first();

    return $block?->expires_at === null
        ? null
        : (int) round(now()->diffInMinutes($block->expires_at));
}

/**
 * Give the rule enough signals to fire, run a tick, and answer how long the
 * block it produced lasts.
 */
function tripRule(string $ip, string $scope = '', array $attributes = []): ?int
{
    foreach (range(1, 3) as $ignored) {
        logEntry($ip, $attributes);
    }

    test()->service->run();

    return blockMinutes($ip, $scope);
}

it('lengthens the block each time the same address comes back', function () {
    expect(tripRule('1.2.3.4'))->toBe(60);

    // Unblocked between rounds the way watchtower:cleanup drops a block once
    // it lapses — which is the case escalation exists for, and the reason
    // the count can't live on the block row.
    $this->blacklist->unblock('1.2.3.4');
    expect(tripRule('1.2.3.4'))->toBe(360);

    $this->blacklist->unblock('1.2.3.4');
    expect(tripRule('1.2.3.4'))->toBe(1440);

    // The top rung repeats rather than running off the end of the list.
    $this->blacklist->unblock('1.2.3.4');
    expect(tripRule('1.2.3.4'))->toBe(1440);

    expect(IpOffence::where('ip', '1.2.3.4')->value('offence_count'))->toBe(4);
});

it('starts again from the bottom once the count has decayed', function () {
    expect(tripRule('1.2.3.4'))->toBe(60);

    $this->blacklist->unblock('1.2.3.4');
    expect(tripRule('1.2.3.4'))->toBe(360);

    $this->blacklist->unblock('1.2.3.4');

    $this->travel(31)->days();

    // Fresh signals: the earlier rows are far outside the rule's window now.
    expect(tripRule('1.2.3.4'))->toBe(60);
    expect(IpOffence::where('ip', '1.2.3.4')->value('offence_count'))->toBe(1);
});

it('does not spend a rung on a warn-mode near miss', function () {
    config()->set('watchtower.auto_block.mode', 'warn');

    expect(tripRule('1.2.3.4'))->toBeNull();
    expect(IpOffence::count())->toBe(0);

    config()->set('watchtower.auto_block.mode', 'block');

    // Still a first offence. A dry run that quietly moved addresses up the
    // ladder would make arming the rule later block people for six hours on
    // the strength of blocks that never happened.
    expect(tripRule('1.2.3.4'))->toBe(60);
});

it('does not spend a rung on an address held back for being shared', function () {
    // Three distinct signed-in users behind one address: a gateway, not one
    // bad actor, so the block is held back and nothing is counted.
    foreach ([1, 2, 3] as $userId) {
        logEntry('1.2.3.4', ['user_id' => $userId]);
    }

    $this->service->run();

    expect(blockMinutes('1.2.3.4'))->toBeNull();
    expect(IpOffence::count())->toBe(0);
});

it('keeps every block at the flat duration while escalation is off', function () {
    config()->set('watchtower.auto_block.escalation.enabled', false);

    expect(tripRule('1.2.3.4'))->toBe(60);

    $this->blacklist->unblock('1.2.3.4');
    expect(tripRule('1.2.3.4'))->toBe(60);

    // Nothing is written at all, so leaving it off costs no rows.
    expect(IpOffence::count())->toBe(0);
});

it('refuses a rung that would produce a block which has already expired', function () {
    // 0 or less puts expires_at at or before now — a block nobody is blocked
    // by. An escalating ladder that silently stops blocking people is the
    // worst way this feature could fail, so a bad rung falls back instead.
    config()->set('watchtower.auto_block.escalation.repeat_durations', [0, -30]);

    expect(tripRule('1.2.3.4'))->toBe(60);

    $this->blacklist->unblock('1.2.3.4');
    expect(tripRule('1.2.3.4'))->toBe(60);

    expect(BlacklistedIp::where('ip', '1.2.3.4')->value('expires_at'))
        ->not->toBeNull()
        ->and(BlacklistedIp::where('ip', '1.2.3.4')->first()->expires_at->isFuture())
        ->toBeTrue();
});

it('remembers the count across a cache flush', function () {
    expect(tripRule('1.2.3.4'))->toBe(60);
    $this->blacklist->unblock('1.2.3.4');

    Cache::flush();

    expect(tripRule('1.2.3.4'))->toBe(360);
});

it('keeps one ladder for an IPv6 client hopping inside its own prefix', function () {
    // A block covers the whole /64, so a ladder keyed on the bare address
    // would hand an attacker a fresh one for every hop inside the range
    // they are already being blocked in.
    $target = $this->blacklist->normalizeTarget('2001:db8::1');

    foreach (range(1, 3) as $ignored) {
        logEntry('2001:db8::1');
    }
    $this->service->run();

    expect(blockMinutes($target))->toBe(60);

    $this->blacklist->unblock('2001:db8::1');

    // The first address's rows have to go, or they stay inside the rule's
    // window and offend again themselves — which would advance the ladder
    // whether or not the count is keyed on the range, and this test would
    // pass without testing anything.
    DB::table('log_entries')->delete();

    foreach (range(1, 3) as $ignored) {
        logEntry('2001:db8::dead');
    }
    $this->service->run();

    expect(blockMinutes($target))->toBe(360);
    expect(IpOffence::count())->toBe(1);
});

it('counts each scope separately', function () {
    config()->set('watchtower.scopes', ['auth']);
    config()->set('watchtower.auto_block.rules', [[
        'level'          => 'error',
        'count'          => 3,
        'window_minutes' => 5,
        'scope'          => 'auth',
    ]]);

    expect(tripRule('1.2.3.4', 'auth'))->toBe(60);

    $this->blacklist->unblock('1.2.3.4');
    expect(tripRule('1.2.3.4', 'auth'))->toBe(360);

    $this->blacklist->unblock('1.2.3.4');

    // The same address has never offended app-wide, so it starts at the
    // bottom there. Two offences on the login routes shouldn't decide how
    // long a block covering the whole app lasts.
    config()->set('watchtower.auto_block.rules', [[
        'level'          => 'error',
        'count'          => 3,
        'window_minutes' => 5,
    ]]);

    expect(tripRule('1.2.3.4'))->toBe(60);
    expect(IpOffence::count())->toBe(2);
});

it('leaves a manual block on the duration its caller asked for', function () {
    // Escalation is only ever consulted by the auto-block engine. That is
    // also what keeps a block arriving over sync off the ladder: it comes in
    // through block() with the expiry the other environment decided.
    expect(tripRule('1.2.3.4'))->toBe(60);
    $this->blacklist->unblock('1.2.3.4');

    $this->blacklist->block('1.2.3.4', ['expires_at' => now()->addMinutes(5)]);

    expect(blockMinutes('1.2.3.4'))->toBe(5);
    expect(IpOffence::where('ip', '1.2.3.4')->value('offence_count'))->toBe(1);
});

it('ships escalation switched off, with a ladder that only ever lengthens a block', function () {
    // Read the shipped file rather than the merged config, so a test override
    // can't satisfy this.
    $shipped = require __DIR__.'/../../config/watchtower.php';
    $escalation = $shipped['auto_block']['escalation'];

    expect($escalation['enabled'])->toBeFalse()
        ->and($escalation['decay_days'])->toBe(30)
        // Every rung above the flat 60, and each one longer than the last:
        // a ladder that stepped down would make a repeat offence cheaper
        // than the first one.
        ->and($escalation['repeat_durations'])->toBe([360, 1440, 10080])
        ->and(min($escalation['repeat_durations']))
        ->toBeGreaterThan($shipped['auto_block']['block_duration_minutes']);
});

it('forgets a ladder that has gone quiet and keeps one that has not', function () {
    IpOffence::create([
        'ip'               => '1.1.1.1',
        'scope'            => '',
        'offence_count'    => 3,
        'first_offence_at' => now()->subDays(90),
        'last_offence_at'  => now()->subDays(31),
    ]);

    IpOffence::create([
        'ip'               => '2.2.2.2',
        'scope'            => '',
        'offence_count'    => 2,
        'first_offence_at' => now()->subDays(9),
        'last_offence_at'  => now()->subDays(5),
    ]);

    $this->artisan('watchtower:cleanup')->assertSuccessful();

    expect(IpOffence::pluck('ip')->all())->toBe(['2.2.2.2']);
});
