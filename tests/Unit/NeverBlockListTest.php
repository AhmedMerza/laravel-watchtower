<?php

declare(strict_types=1);

use Watchtower\Support\IpRange;
use Watchtower\Support\NeverBlockList;

/**
 * NeverBlockList now canonicalises each list once and keeps the result, so the
 * three middleware that ask per request stop re-parsing the same entries. The
 * memo is keyed on the raw config array; these assert that keying holds, since
 * a memo that went stale would silently start blocking an allow-listed address
 * — the one failure this list exists to prevent.
 */
it('covers a bare address and a range that contains it', function () {
    config()->set('watchtower.never_block', ['203.0.113.7', '198.51.100.0/24']);

    expect(NeverBlockList::neverBlock('203.0.113.7'))->toBeTrue()
        ->and(NeverBlockList::neverBlock('198.51.100.42'))->toBeTrue()
        ->and(NeverBlockList::neverBlock('203.0.113.8'))->toBeFalse()
        ->and(NeverBlockList::neverBlock('192.0.2.1'))->toBeFalse();
});

it('picks up a config change rather than serving a stale parse', function () {
    config()->set('watchtower.never_block', ['203.0.113.7']);
    expect(NeverBlockList::neverBlock('203.0.113.7'))->toBeTrue();

    // The address is removed from the list. A memo that did not key on the
    // source array would keep reporting it as protected.
    config()->set('watchtower.never_block', ['192.0.2.1']);
    expect(NeverBlockList::neverBlock('203.0.113.7'))->toBeFalse()
        ->and(NeverBlockList::neverBlock('192.0.2.1'))->toBeTrue();

    // And back again, so the failure can't be "it only ever reads once".
    config()->set('watchtower.never_block', ['203.0.113.7']);
    expect(NeverBlockList::neverBlock('203.0.113.7'))->toBeTrue();
});

it('keeps the two lists apart', function () {
    // One memo slot per config key: never_block and never_auto_block mean
    // different things, and a shared slot would have them overwrite each other
    // on every alternating call.
    config()->set('watchtower.never_block', ['203.0.113.7']);
    config()->set('watchtower.never_auto_block', ['198.51.100.9']);

    expect(NeverBlockList::neverBlock('203.0.113.7'))->toBeTrue()
        ->and(NeverBlockList::neverBlock('198.51.100.9'))->toBeFalse()
        ->and(NeverBlockList::neverAutoBlock('198.51.100.9'))->toBeTrue()
        ->and(NeverBlockList::neverAutoBlock('203.0.113.7'))->toBeFalse()
        ->and(NeverBlockList::refusesAutoBlock('203.0.113.7'))->toBeTrue()
        ->and(NeverBlockList::refusesAutoBlock('198.51.100.9'))->toBeTrue()
        ->and(NeverBlockList::refusesAutoBlock('192.0.2.1'))->toBeFalse();
});

it('drops a malformed entry instead of failing the whole list', function () {
    // An operator typo on one line must not take the rest of the allow-list
    // down with it — nor the request that is consulting it.
    config()->set('watchtower.never_block', ['not-an-ip', ['nested'], null, '203.0.113.7']);

    expect(NeverBlockList::neverBlock('203.0.113.7'))->toBeTrue()
        ->and(NeverBlockList::neverBlock('203.0.113.8'))->toBeFalse();
});

it('answers false for an unparseable address', function () {
    config()->set('watchtower.never_block', ['0.0.0.0/0']);

    // Even against a list that covers everything: there is no address here to
    // be covered, so the allow-list cannot vouch for it.
    expect(NeverBlockList::neverBlock('not-an-ip'))->toBeFalse();
});

it('matches an IPv6 address through its canonical form', function () {
    config()->set('watchtower.never_block', ['2001:0db8:0000:0000:0000:0000:0000:0001']);

    expect(NeverBlockList::neverBlock('2001:db8::1'))->toBeTrue();
});

it('ignores surrounding whitespace in an entry', function () {
    config()->set('watchtower.never_block', ["  203.0.113.7\t"]);

    expect(NeverBlockList::neverBlock('203.0.113.7'))->toBeTrue();
});

it('agrees with IpRange::covers, which is what it replaced at the call sites', function () {
    $entries = ['203.0.113.7', '198.51.100.0/24', '2001:db8::/32', 'not-an-ip'];
    config()->set('watchtower.never_block', $entries);

    foreach (['203.0.113.7', '203.0.113.8', '198.51.100.42', '2001:db8::1', '2001:db9::1'] as $ip) {
        $canonical = IpRange::canonical($ip);

        expect(NeverBlockList::neverBlock($ip))
            ->toBe($canonical !== null && IpRange::covers($entries, $canonical), "ip: {$ip}");
    }
});
