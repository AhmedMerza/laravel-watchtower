<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Queue;
use LogScope\Http\Middleware\Authorize;
use Watchtower\Enums\BlockSource;
use Watchtower\Events\IpBlocked;
use Watchtower\Models\BlacklistedIp;
use Watchtower\Services\BlacklistCache;

beforeEach(function () {
    // Use the array cache store — real cache, no Redis-facade mocking.
    // Watchtower's BlacklistCache reads `watchtower.cache.store`, so we
    // pin both that and Laravel's default cache to 'array' for isolation.
    config()->set('cache.default', 'array');
    config()->set('watchtower.cache.store', 'array');
    Cache::flush();

    Event::fake();
    Queue::fake();

    // Bypass LogScope's Authorize middleware in tests
    $this->withoutMiddleware(Authorize::class);
});

it('blocks an IP via the API and updates the database', function () {
    $response = $this->postJson('/logscope/watchtower/api/block', [
        'ip'     => '10.0.0.1',
        'reason' => 'suspicious traffic',
    ]);

    $response->assertStatus(200)
        ->assertJsonPath('data.ip', '10.0.0.1')
        ->assertJsonPath('data.reason', 'suspicious traffic');

    $this->assertDatabaseHas('blacklisted_ips', [
        'ip'     => '10.0.0.1',
        'source' => 'manual',
    ]);

    Event::assertDispatched(IpBlocked::class);
});

it('returns 422 when trying to block a whitelisted IP', function () {
    config()->set('watchtower.never_block', ['127.0.0.1']);

    $response = $this->postJson('/logscope/watchtower/api/block', ['ip' => '127.0.0.1']);

    $response->assertStatus(422)
        ->assertJsonStructure(['error']);
});

it('returns 500, not the never-block 422, when the block cannot be written', function () {
    config()->set('app.debug', false);
    failBlacklistInserts();

    $response = $this->postJson('/logscope/watchtower/api/block', ['ip' => '10.0.0.1']);

    $response->assertStatus(500);
    // A QueryException's message carries the SQL and its bindings.
    expect($response->getContent())->not->toContain('blacklisted_ips');
});

it('unblocks an IP via the API', function () {
    BlacklistedIp::create([
        'ip'         => '10.0.0.2',
        'source'     => BlockSource::Manual,
        'source_env' => 'testing',
    ]);

    $response = $this->deleteJson('/logscope/watchtower/api/block/10.0.0.2');

    $response->assertStatus(200)
        ->assertJsonPath('deleted', true);

    $this->assertDatabaseMissing('blacklisted_ips', ['ip' => '10.0.0.2']);
});

it('returns the correct status for a blocked IP', function () {
    BlacklistedIp::create([
        'ip'         => '10.0.0.3',
        'source'     => BlockSource::Manual,
        'source_env' => 'testing',
        'expires_at' => null,
    ]);

    // status() checks the cache as truth — write a permanent-block entry
    // (empty string value) for the IP so isBlocked() returns true.
    Cache::store('array')->put('watchtower:blacklist:ip:10.0.0.3', '', 3600);

    $response = $this->getJson('/logscope/watchtower/api/status/10.0.0.3');

    $response->assertStatus(200)
        ->assertJsonPath('blocked', true);
});

it('returns the correct status for an unblocked IP', function () {
    $response = $this->getJson('/logscope/watchtower/api/status/9.9.9.9');

    $response->assertStatus(200)
        ->assertJsonPath('blocked', false);
});

it('returns the full list of active blocks', function () {
    BlacklistedIp::create(['ip' => '1.1.1.1', 'source' => BlockSource::Manual, 'source_env' => 'testing']);
    BlacklistedIp::create(['ip' => '2.2.2.2', 'source' => BlockSource::Auto, 'source_env' => 'testing']);

    $response = $this->getJson('/logscope/watchtower/api/blocks');

    $response->assertStatus(200)
        ->assertJsonCount(2, 'data');
});

it('does not return expired blocks in the list', function () {
    BlacklistedIp::create(['ip' => '1.1.1.1', 'source' => BlockSource::Manual, 'source_env' => 'testing', 'expires_at' => now()->subHour()]);
    BlacklistedIp::create(['ip' => '2.2.2.2', 'source' => BlockSource::Manual, 'source_env' => 'testing', 'expires_at' => now()->addHour()]);

    $response = $this->getJson('/logscope/watchtower/api/blocks');

    $response->assertStatus(200)
        ->assertJsonCount(1, 'data');
});

describe('ranges', function () {
    it('blocks a CIDR range', function (string $ip, string $stored) {
        $this->postJson('/logscope/watchtower/api/block', ['ip' => $ip])
            ->assertOk()
            ->assertJsonPath('data.ip', $stored);
    })->with([
        'IPv4'              => ['203.0.113.0/24', '203.0.113.0/24'],
        'IPv6'              => ['2001:db8::/48', '2001:db8::/48'],
        'host bits set'     => ['203.0.113.9/24', '203.0.113.0/24'],
        'single IPv6 → /64' => ['2001:db8::1', '2001:db8::/64'],
    ]);

    it('refuses a range broader than /16 or /32 without force', function (string $ip) {
        $this->postJson('/logscope/watchtower/api/block', ['ip' => $ip])
            ->assertStatus(422)
            ->assertJsonValidationErrors(['ip' => 'force=true']);

        $this->assertDatabaseCount('blacklisted_ips', 0);
    })->with(['10.0.0.0/15', '2001:d00::/31']);

    it('blocks a broad range when force is sent', function () {
        $this->postJson('/logscope/watchtower/api/block', ['ip' => '10.0.0.0/8', 'force' => true])
            ->assertOk()
            ->assertJsonPath('data.ip', '10.0.0.0/8');
    });

    it('refuses something that is not an IP or range', function (mixed $ip) {
        $this->postJson('/logscope/watchtower/api/block', ['ip' => $ip])
            ->assertStatus(422)
            ->assertJsonValidationErrors('ip');
    })->with(['10.0.0.0/33', '10.0.0.0/1a', 'example.com', 123]);

    it('unblocks a range by its CIDR in the path', function (string $path) {
        $this->postJson('/logscope/watchtower/api/block', ['ip' => '203.0.113.0/24'])->assertOk();

        $this->deleteJson('/logscope/watchtower/api/block/'.$path)
            ->assertOk()
            ->assertJsonPath('deleted', true);

        $this->assertDatabaseCount('blacklisted_ips', 0);
    })->with([
        'slash'   => ['203.0.113.0/24'],
        'encoded' => ['203.0.113.0%2F24'],
    ]);

    it('reports the range that blocks an IP', function () {
        $this->postJson('/logscope/watchtower/api/block', ['ip' => '203.0.113.0/24'])->assertOk();

        $this->getJson('/logscope/watchtower/api/status/203.0.113.9')
            ->assertOk()
            ->assertJsonPath('blocked', true)
            ->assertJsonPath('data.ip', '203.0.113.0/24');
    });

    it('refuses an IP containing a NUL byte with a 422, not a 500', function () {
        // inet_pton() throws on a NUL byte, and `@` doesn't suppress that.
        // It has to sit inside the string: TrimStrings strips a trailing one.
        $this->postJson('/logscope/watchtower/api/block', ['ip' => "1.2.3\u{0000}.4"])
            ->assertStatus(422)
            ->assertJsonValidationErrors('ip');
    });

    it('reports a never-block address covered by a blocked range as unblocked', function () {
        config()->set('watchtower.never_block', ['203.0.113.9']);
        $this->postJson('/logscope/watchtower/api/block', ['ip' => '203.0.113.0/24'])->assertOk();

        $this->getJson('/logscope/watchtower/api/status/203.0.113.9')
            ->assertOk()
            ->assertJsonPath('blocked', false);
    });

    it('reports a range covered by a wider blocked range', function () {
        $this->postJson('/logscope/watchtower/api/block', ['ip' => '203.0.113.0/24'])->assertOk();

        $this->getJson('/logscope/watchtower/api/status/203.0.113.0%2F25')
            ->assertOk()
            ->assertJsonPath('blocked', true)
            ->assertJsonPath('data.ip', '203.0.113.0/24');
    });

    it('reports an expired range as unblocked', function () {
        BlacklistedIp::create([
            'ip'         => '203.0.113.0/24',
            'source'     => BlockSource::Manual,
            'source_env' => 'testing',
            'expires_at' => now()->subMinute(),
        ]);

        $this->getJson('/logscope/watchtower/api/status/203.0.113.0%2F24')
            ->assertOk()
            ->assertJsonPath('blocked', false)
            ->assertJsonPath('data.ip', '203.0.113.0/24');
    });

    it('reports the status of a range', function () {
        $this->postJson('/logscope/watchtower/api/block', ['ip' => '203.0.113.0/24'])->assertOk();

        $this->getJson('/logscope/watchtower/api/status/203.0.113.0%2F24')
            ->assertOk()
            ->assertJsonPath('blocked', true)
            ->assertJsonPath('data.ip', '203.0.113.0/24');

        $this->getJson('/logscope/watchtower/api/status/198.51.100.0%2F24')
            ->assertOk()
            ->assertJsonPath('blocked', false)
            ->assertJsonPath('data', null);
    });
});
