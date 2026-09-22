<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Queue;
use Illuminate\Support\Str;
use Watchtower\Enums\BlockSource;
use Watchtower\Models\BlacklistedIp;

/**
 * #74 — a lapsed local block used to turn away a live synced one.
 *
 * The never-downgrade rule protects a local decision that is IN FORCE. The
 * lookup behind it had no expiry filter, so a block that expired an hour ago
 * — whose row `watchtower:cleanup` had not swept yet — still refused the
 * master's live block, for up to a day. The master considered the address
 * blocked, this node did not block it, and the run reported the disagreement
 * as "local blocks preserved".
 */
beforeEach(function () {
    Event::fake();
    Queue::fake();
});

/** A local block that has already expired, but whose row is still here. */
function lapsedLocalBlock(string $ip, BlockSource $source = BlockSource::Manual): BlacklistedIp
{
    return BlacklistedIp::create([
        'id'         => (string) Str::ulid(),
        'ip'         => $ip,
        'reason'     => 'lapsed local block',
        'source'     => $source,
        'source_env' => 'local',
        'scope'      => '',
        'expires_at' => now()->subHour(),
    ]);
}

/** A local block that is still in force. */
function liveLocalBlock(string $ip, BlockSource $source = BlockSource::Manual): BlacklistedIp
{
    return BlacklistedIp::create([
        'id'         => (string) Str::ulid(),
        'ip'         => $ip,
        'reason'     => 'live local block',
        'source'     => $source,
        'source_env' => 'local',
        'scope'      => '',
        'expires_at' => now()->addHour(),
    ]);
}

it('lets a synced block replace a lapsed local one', function () {
    $lapsed = lapsedLocalBlock('1.2.3.4');

    postSigned($this, (string) json_encode([
        'ip'         => '1.2.3.4',
        'reason'     => 'Master says so',
        'source_env' => 'satellite-eu',
    ]))->assertOk()->assertJsonPath('applied', true);

    $row = BlacklistedIp::find($lapsed->id);

    expect($row->source)->toBe(BlockSource::Sync)
        ->and($row->reason)->toBe('Master says so')
        ->and($row->isExpired())->toBeFalse();
});

it('still refuses to downgrade a LIVE local manual block', function () {
    // The rule the guard exists for, unchanged.
    liveLocalBlock('1.2.3.4');

    postSigned($this, (string) json_encode([
        'ip'         => '1.2.3.4',
        'reason'     => 'Master says so',
        'source_env' => 'satellite-eu',
    ]))->assertOk()->assertJsonPath('applied', false);

    expect(BlacklistedIp::where('ip', '1.2.3.4')->first()->reason)->toBe('live local block');
});

it('still refuses to downgrade a live local AUTO block', function () {
    liveLocalBlock('1.2.3.4', BlockSource::Auto);

    postSigned($this, (string) json_encode([
        'ip'         => '1.2.3.4',
        'source_env' => 'satellite-eu',
    ]))->assertOk()->assertJsonPath('applied', false);
});

it('replaces a lapsed local block rather than creating a second row', function () {
    // updateOrCreate still matches on (ip, scope) without the expiry filter,
    // so the lapsed row is updated. A second row would break the unique
    // index and lose the block entirely.
    lapsedLocalBlock('1.2.3.4');

    postSigned($this, (string) json_encode(['ip' => '1.2.3.4', 'source_env' => 'satellite-eu']))->assertOk();

    expect(BlacklistedIp::where('ip', '1.2.3.4')->count())->toBe(1);
});

it('does not let a lapsed local block hide a never_auto_block refusal', function () {
    // Order matters: the allow-list is consulted before the downgrade guard,
    // so a lapsed row must not change the answer.
    config()->set('watchtower.never_auto_block', ['5.6.7.8']);
    lapsedLocalBlock('5.6.7.8');

    postSigned($this, (string) json_encode([
        'ip'         => '5.6.7.8',
        'source_env' => 'satellite-eu',
        'source'     => 'auto',
    ]))->assertStatus(422);

    expect(BlacklistedIp::where('ip', '5.6.7.8')->first()->reason)->toBe('lapsed local block');
});

it('applies the lapsed-row exemption to an IPv6 address too', function () {
    // The guard queries normalizeTarget($ip) — a single IPv6 address widened
    // to its /64 — while the allow-lists ask about the raw address. Nothing
    // proved the exemption still works once the stored target and the
    // incoming address stop being the same string.
    $prefix = '2001:db8:1:1::/64';

    BlacklistedIp::create([
        'id'         => (string) Str::ulid(),
        'ip'         => $prefix,
        'reason'     => 'lapsed local block',
        'source'     => BlockSource::Manual,
        'source_env' => 'local',
        'scope'      => '',
        'expires_at' => now()->subHour(),
    ]);

    postSigned($this, (string) json_encode([
        'ip'         => '2001:db8:1:1::5',
        'reason'     => 'Master says so',
        'source_env' => 'satellite-eu',
    ]))->assertOk()->assertJsonPath('applied', true);

    $row = BlacklistedIp::where('ip', $prefix)->first();

    expect($row)->not->toBeNull()
        ->and($row->source)->toBe(BlockSource::Sync)
        ->and($row->reason)->toBe('Master says so')
        ->and(BlacklistedIp::count())->toBe(1);
});
