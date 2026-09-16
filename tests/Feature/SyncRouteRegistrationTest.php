<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Route;
use Watchtower\Support\SyncSignature;

// No sync secret is configured in the base TestCase, so this file exercises
// the "not a master" case: an environment that should expose nothing.

it('registers no sync routes without a shared secret', function () {
    expect(Route::has('watchtower.sync.blocks'))->toBeFalse()
        ->and(Route::has('watchtower.sync.receive'))->toBeFalse();
});

it('404s the sync paths without a shared secret', function () {
    $this->getJson(SyncSignature::PULL_PATH)->assertNotFound();
    $this->postJson(SyncSignature::PUSH_PATH, ['ip' => '1.2.3.4'])->assertNotFound();
});
