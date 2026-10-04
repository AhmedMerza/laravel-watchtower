<?php

declare(strict_types=1);

use Watchtower\Enums\BlockSource;
use Watchtower\Models\BlacklistedIp;
use Watchtower\Support\SyncSignature;

// signedHeaders() is defined in SyncRoutesTest.php, which Pest loads for this
// directory too.

it('leaves feed blocks out of the blocklist a satellite pulls', function () {
    // Every environment imports the feeds itself. A satellite pulling the
    // master's copy would store thousands of them as `sync` rows that its
    // own import never cleans up (#21).
    BlacklistedIp::create(['ip' => '1.2.3.4', 'source' => BlockSource::Manual]);
    BlacklistedIp::create(['ip' => '1.10.16.0/20', 'source' => BlockSource::Feed, 'blocked_by' => 'feed:drop']);

    $response = $this->withHeaders(signedHeaders('GET', SyncSignature::PULL_PATH))
        ->get(SyncSignature::PULL_PATH)
        ->assertOk();

    expect(collect($response->json('data'))->pluck('ip')->all())->toBe(['1.2.3.4']);
});
