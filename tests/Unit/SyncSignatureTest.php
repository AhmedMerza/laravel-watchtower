<?php

declare(strict_types=1);

use Watchtower\Support\SyncSignature;

it('trims the secret, so a stray .env space cannot desync the fleet', function () {
    config()->set('watchtower.sync.secret', "  a-long-random-secret\n");

    expect(SyncSignature::secret())->toBe('a-long-random-secret');
});

it('treats the string "0" as a real secret, not as absent', function () {
    // PHP considers "0" falsy. Reading it with a truthiness test made the
    // route registration and the middleware disagree about whether sync was
    // configured at all.
    config()->set('watchtower.sync.secret', '0');

    expect(SyncSignature::secret())->toBe('0');
});

it('reports an unset, empty or whitespace-only secret as absent', function (mixed $value) {
    config()->set('watchtower.sync.secret', $value);

    expect(SyncSignature::secret())->toBe('');
})->with([null, '', '   ', "\t\n"]);
