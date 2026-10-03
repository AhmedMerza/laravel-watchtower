<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Queue;
use LogScope\Http\Middleware\Authorize;
use Watchtower\Models\BlacklistedIp;
use Watchtower\Support\BlockScope;

beforeEach(function () {
    config()->set('cache.default', 'array');
    config()->set('watchtower.cache.store', 'array');
    config()->set('watchtower.scopes', ['auth']);
    Cache::flush();

    Event::fake();
    Queue::fake();

    $this->withoutMiddleware(Authorize::class);
});

it('blocks an IP in a scope via the API', function () {
    $this->postJson('/logscope/watchtower/api/block', [
        'ip'    => '10.0.0.1',
        'scope' => 'auth',
    ])->assertOk()->assertJsonPath('data.scope', 'auth');

    $this->assertDatabaseHas('blacklisted_ips', ['ip' => '10.0.0.1', 'scope' => 'auth']);
});

it('refuses a scope the config does not declare', function () {
    $this->postJson('/logscope/watchtower/api/block', [
        'ip'    => '10.0.0.1',
        'scope' => 'atuh',
    ])->assertStatus(422)->assertJsonValidationErrors('scope');

    $this->assertDatabaseMissing('blacklisted_ips', ['ip' => '10.0.0.1']);
});

it('stores a block with no scope as global', function () {
    $this->postJson('/logscope/watchtower/api/block', ['ip' => '10.0.0.1'])->assertOk();

    $this->assertDatabaseHas('blacklisted_ips', ['ip' => '10.0.0.1', 'scope' => BlockScope::GLOBAL]);
});

it('lets one address hold a global block and a scoped one at once', function () {
    $this->postJson('/logscope/watchtower/api/block', ['ip' => '10.0.0.1'])->assertOk();
    $this->postJson('/logscope/watchtower/api/block', ['ip' => '10.0.0.1', 'scope' => 'auth'])->assertOk();

    expect(BlacklistedIp::where('ip', '10.0.0.1')->count())->toBe(2);
});

it('reports a scoped block under scopes, and not as blocked app-wide', function () {
    $this->postJson('/logscope/watchtower/api/block', ['ip' => '10.0.0.1', 'scope' => 'auth'])->assertOk();

    // `blocked` answers the question the global middleware answers. Saying
    // true here would tell a caller the address is shut out when it can still
    // reach everything except the routes naming this scope.
    $this->getJson('/logscope/watchtower/api/status/10.0.0.1')
        ->assertOk()
        ->assertJsonPath('blocked', false)
        ->assertJsonPath('scopes.auth.ip', '10.0.0.1');
});

it('unblocks every scope by default', function () {
    $this->postJson('/logscope/watchtower/api/block', ['ip' => '10.0.0.1'])->assertOk();
    $this->postJson('/logscope/watchtower/api/block', ['ip' => '10.0.0.1', 'scope' => 'auth'])->assertOk();

    $this->deleteJson('/logscope/watchtower/api/block/10.0.0.1')
        ->assertOk()
        ->assertJsonPath('deleted', true);

    expect(BlacklistedIp::where('ip', '10.0.0.1')->count())->toBe(0);
});

it('unblocks only the named scope when one is given', function () {
    $this->postJson('/logscope/watchtower/api/block', ['ip' => '10.0.0.1'])->assertOk();
    $this->postJson('/logscope/watchtower/api/block', ['ip' => '10.0.0.1', 'scope' => 'auth'])->assertOk();

    $this->deleteJson('/logscope/watchtower/api/block/10.0.0.1?scope=auth')->assertOk();

    expect(BlacklistedIp::where('ip', '10.0.0.1')->pluck('scope')->all())
        ->toBe([BlockScope::GLOBAL]);
});

// Whether a block reaches the master (and that a scoped one doesn't — the
// sync payload carries no scope, so the master would store it as global and
// hand every satellite an app-wide block nobody asked for, until #37 widens
// the wire format) is DispatchBlockToTargets's decision now, not block()'s —
// Event::fake() here would stop that queued listener from ever running, so
// that coverage moved to tests/Unit/DispatchBlockToTargetsTest.php, which
// exercises the real listener directly instead of faking the event away.

it('reports only the scopes an address is actually blocked in', function () {
    config()->set('watchtower.scopes', ['auth', 'admin']);

    $this->postJson('/logscope/watchtower/api/block', ['ip' => '10.0.0.1', 'scope' => 'auth'])->assertOk();

    // Two scopes declared, one blocked. `scopes` must carry the blocked one
    // and nothing for the other — every earlier test declared a single scope,
    // so the loop body always ran exactly once.
    $this->getJson('/logscope/watchtower/api/status/10.0.0.1')
        ->assertOk()
        ->assertJsonPath('blocked', false)
        ->assertJsonPath('scopes.auth.ip', '10.0.0.1')
        ->assertJsonMissingPath('scopes.admin');
});
