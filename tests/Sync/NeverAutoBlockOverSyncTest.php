<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Queue;
use Watchtower\Enums\BlockSource;
use Watchtower\Models\BlacklistedIp;

/**
 * #56 — `never_auto_block` across a fleet.
 *
 * The list means "automation may not touch this, an admin still may". Before
 * this, it stopped at the node boundary: a satellite's RULE could push a
 * block and the master applied it, because the payload never said what had
 * decided it. The fix is a `source` field on the wire, and the tests that
 * matter are the three below — the rule is refused, the admin is not, and an
 * old satellite that sends neither keeps working exactly as it did.
 */
beforeEach(function () {
    Event::fake();
    Queue::fake();

    config()->set('watchtower.never_auto_block', ['5.6.7.8']);
});

/** The push body a satellite sends, with `source` overridable. */
function pushBody(array $overrides = []): string
{
    return (string) json_encode(array_merge([
        'ip'         => '5.6.7.8',
        'reason'     => 'Brute force',
        'source_env' => 'satellite-eu',
    ], $overrides));
}

it('refuses a block another environment\'s automation pushed', function () {
    postSigned($this, pushBody(['source' => 'auto']))
        ->assertStatus(422)
        ->assertJsonPath('error', fn (string $e): bool => str_contains($e, 'never-auto-block'));

    expect(BlacklistedIp::where('ip', '5.6.7.8')->exists())->toBeFalse();
});

it('applies the same address when a satellite admin blocked it by hand', function () {
    // The entire point of never_auto_block rather than never_block: an admin
    // keeps the power the rule is denied.
    postSigned($this, pushBody(['source' => 'manual']))->assertOk();

    expect(BlacklistedIp::where('ip', '5.6.7.8')->exists())->toBeTrue();
});

it('keeps accepting a satellite too old to send a source', function () {
    // A mixed-version fleet during a rolling upgrade. Treating the absent
    // field as "auto" would start silently refusing this satellite's ADMIN
    // blocks the moment the master was upgraded — a new failure caused by
    // upgrading, which is the thing a protocol change must not do.
    postSigned($this, pushBody())->assertOk();

    expect(BlacklistedIp::where('ip', '5.6.7.8')->exists())->toBeTrue();
});

it('still refuses a never_block address whatever the source says', function () {
    config()->set('watchtower.never_block', ['9.9.9.9']);

    foreach (['auto', 'manual', null] as $source) {
        postSigned($this, pushBody(array_filter([
            'ip'     => '9.9.9.9',
            'source' => $source,
        ], static fn ($v): bool => $v !== null)))->assertStatus(422);
    }

    expect(BlacklistedIp::where('ip', '9.9.9.9')->exists())->toBeFalse();
});

it('rejects a source that is not a real block source', function () {
    postSigned($this, pushBody(['source' => 'whatever']))->assertStatus(422);
});

it('does not apply never_auto_block to an address that is not on the list', function () {
    postSigned($this, pushBody(['ip' => '1.2.3.4', 'source' => 'auto']))->assertOk();

    expect(BlacklistedIp::where('ip', '1.2.3.4')->first()->source)->toBe(BlockSource::Sync);
});

it('refuses a pushed `sync` source, which no honest satellite can produce', function () {
    // PushBlockToMaster returns early on a Sync record, so a satellite never
    // relays a block it received. The push contract is manual-or-auto, and
    // validation now says so rather than accepting a third value it has no
    // meaning for. The PULL direction is different — see the relayed-origin
    // test in SyncCommandTest, where a master's own row really can be `sync`.
    postSigned($this, pushBody(['source' => 'sync']))->assertStatus(422);

    expect(BlacklistedIp::where('ip', '5.6.7.8')->exists())->toBeFalse();
});
