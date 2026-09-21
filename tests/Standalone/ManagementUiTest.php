<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Queue;
use Illuminate\Support\Facades\Route;
use Watchtower\Enums\BlockSource;
use Watchtower\Http\Middleware\Authorize;
use Watchtower\Models\BlacklistedIp;
use Watchtower\Support\BlockScope;

beforeEach(function () {
    Event::fake();
    Queue::fake();
    config()->set('watchtower.scopes', ['auth']);
});

/**
 * Signed in as a user the app's Gate allows. `allowAdminOnly()` and
 * `eloquentUser()` come from ManagementApiAuthorizationTest.
 */
function signedInAdmin(object $test): object
{
    allowAdminOnly();

    return $test->actingAs(eloquentUser('admin@example.com'));
}

/**
 * A form POST from the page.
 *
 * Laravel skips its CSRF check only in `testing`, and Laravel 12 and 13 put
 * different CSRF middleware in the `web` group, so send a real token — the
 * page's own forms do.
 */
function uiPost(object $test, string $uri, array $data = []): object
{
    return $test->withSession(['_token' => 'test-token'])
        ->withHeader('X-CSRF-TOKEN', 'test-token')
        ->post($uri, $data + ['_token' => 'test-token']);
}

function blockRow(string $ip, array $attributes = []): BlacklistedIp
{
    return BlacklistedIp::create(array_merge([
        'ip'         => $ip,
        'source'     => BlockSource::Manual,
        'source_env' => 'testing',
    ], $attributes));
}

it('mounts the page at the route prefix behind the Gate check', function () {
    $route = Route::getRoutes()->getByName('watchtower.ui.index');

    expect($route->uri())->toBe('watchtower')
        ->and($route->gatherMiddleware())->toBe(['web', Authorize::class]);
});

it('refuses an anonymous browser request outside local', function () {
    $this->get('/watchtower')->assertForbidden();
});

it('refuses a user the app\'s Gate does not allow', function () {
    allowAdminOnly();

    $this->actingAs(eloquentUser('someone@example.com'))
        ->get('/watchtower')
        ->assertForbidden();
});

it('lists the active blocks', function () {
    blockRow('10.0.0.1', ['reason' => 'Brute force', 'blocked_by' => 'ops@example.com']);

    signedInAdmin($this)->get('/watchtower')
        ->assertOk()
        ->assertSee('10.0.0.1')
        ->assertSee('Brute force')
        ->assertSee('ops@example.com');
});

it('says so when nothing is blocked', function () {
    signedInAdmin($this)->get('/watchtower')
        ->assertOk()
        ->assertSee('Nothing is blocked.');
});

it('blocks an address from the form', function () {
    uiPost(signedInAdmin($this), '/watchtower/block', [
        'ip'       => '203.0.113.4',
        'reason'   => 'Scanning',
        'duration' => '24h',
    ])->assertRedirect()->assertSessionHas('watchtower_status');

    $block = BlacklistedIp::firstWhere('ip', '203.0.113.4');

    expect($block)->not->toBeNull()
        ->and($block->reason)->toBe('Scanning')
        ->and($block->scope)->toBe(BlockScope::GLOBAL)
        ->and($block->source)->toBe(BlockSource::Manual)
        ->and($block->blocked_by)->toBe('admin@example.com')
        ->and($block->expires_at->timestamp)
        ->toBeGreaterThan(now()->addHours(23)->timestamp)
        ->and($block->expires_at->timestamp)
        ->toBeLessThanOrEqual(now()->addHours(24)->timestamp);
});

it('blocks permanently when the form says so', function () {
    uiPost(signedInAdmin($this), '/watchtower/block', [
        'ip'       => '203.0.113.5',
        'duration' => 'permanent',
    ])->assertRedirect();

    expect(BlacklistedIp::firstWhere('ip', '203.0.113.5')->expires_at)->toBeNull();
});

it('blocks a range in a scope', function () {
    uiPost(signedInAdmin($this), '/watchtower/block', [
        'ip'       => '203.0.113.0/24',
        'duration' => '1h',
        'scope'    => 'auth',
    ])->assertRedirect();

    expect(BlacklistedIp::firstWhere('ip', '203.0.113.0/24')->scope)->toBe('auth');
});

it('refuses a scope no route carries', function () {
    uiPost(signedInAdmin($this), '/watchtower/block', [
        'ip'       => '203.0.113.6',
        'duration' => '1h',
        'scope'    => 'atuh',
    ])->assertSessionHasErrors('scope');

    expect(BlacklistedIp::count())->toBe(0);
});

it('refuses a target that is not an address or a range', function () {
    uiPost(signedInAdmin($this), '/watchtower/block', [
        'ip'       => 'not-an-ip',
        'duration' => '1h',
    ])->assertSessionHasErrors('ip');

    expect(BlacklistedIp::count())->toBe(0);
});

it('refuses a range broader than the limit unless the form forces it', function () {
    $payload = ['ip' => '10.0.0.0/8', 'duration' => '1h'];

    uiPost(signedInAdmin($this), '/watchtower/block', $payload)->assertSessionHasErrors('ip');
    expect(BlacklistedIp::count())->toBe(0);

    uiPost(signedInAdmin($this), '/watchtower/block', $payload + ['force' => '1'])->assertRedirect();
    expect(BlacklistedIp::firstWhere('ip', '10.0.0.0/8'))->not->toBeNull();
});

it('shows why a never_block address was refused', function () {
    config()->set('watchtower.never_block', ['127.0.0.1']);

    uiPost(signedInAdmin($this), '/watchtower/block', [
        'ip'       => '127.0.0.1',
        'duration' => '1h',
    ])->assertSessionHasErrors('ip');

    expect(BlacklistedIp::count())->toBe(0);
});

it('asks before unblocking, and unblocks when confirmed', function () {
    $block = blockRow('10.0.0.1');

    // The list offers a link that asks, not a button that acts: nothing on
    // the unconfirmed page can POST an unblock.
    signedInAdmin($this)->get('/watchtower')
        ->assertOk()
        ->assertSee('confirm='.$block->id, escape: false)
        ->assertDontSee('watchtower/unblock', escape: false);

    signedInAdmin($this)->get('/watchtower?confirm='.$block->id)
        ->assertOk()
        ->assertSee('watchtower/unblock', escape: false);

    uiPost(signedInAdmin($this), '/watchtower/unblock', ['id' => $block->id])
        ->assertRedirect()
        ->assertSessionHas('watchtower_status');

    expect(BlacklistedIp::count())->toBe(0);
});

it('lifts only the row it was asked to lift', function () {
    $global = blockRow('10.0.0.1');
    blockRow('10.0.0.1', ['scope' => 'auth']);

    uiPost(signedInAdmin($this), '/watchtower/unblock', ['id' => $global->id])->assertRedirect();

    expect(BlacklistedIp::pluck('scope')->all())->toBe(['auth']);
});

it('says so when the block is already gone', function () {
    $block = blockRow('10.0.0.1');
    $id = $block->id;
    $block->delete();

    uiPost(signedInAdmin($this), '/watchtower/unblock', ['id' => $id])
        ->assertRedirect()
        ->assertSessionHas('watchtower_status', 'That block is already gone.');
});

it('filters by source', function () {
    blockRow('10.0.0.1', ['source' => BlockSource::Manual]);
    blockRow('10.0.0.2', ['source' => BlockSource::Auto]);

    signedInAdmin($this)->get('/watchtower?source=auto')
        ->assertOk()
        ->assertSee('10.0.0.2')
        ->assertDontSee('10.0.0.1');
});

it('hides expired blocks until asked for them', function () {
    blockRow('10.0.0.1', ['expires_at' => now()->subHour()]);
    blockRow('10.0.0.2');

    signedInAdmin($this)->get('/watchtower')
        ->assertOk()
        ->assertSee('10.0.0.2')
        ->assertDontSee('10.0.0.1');

    signedInAdmin($this)->get('/watchtower?state=expired')
        ->assertOk()
        ->assertSee('10.0.0.1')
        ->assertDontSee('10.0.0.2');

    signedInAdmin($this)->get('/watchtower?state=all')
        ->assertOk()
        ->assertSee('10.0.0.1')
        ->assertSee('10.0.0.2');
});

it('ignores a filter the query string made up', function () {
    blockRow('10.0.0.1');

    signedInAdmin($this)->get('/watchtower?source=nonsense&state=nonsense')
        ->assertOk()
        ->assertSee('10.0.0.1');
});

it('paginates', function () {
    foreach (range(1, 26) as $n) {
        blockRow('10.0.1.'.$n, ['created_at' => now()->subMinutes($n)]);
    }

    signedInAdmin($this)->get('/watchtower')
        ->assertOk()
        ->assertSee('Page 1 of 2')
        ->assertDontSee('10.0.1.26');

    signedInAdmin($this)->get('/watchtower?page=2')
        ->assertOk()
        ->assertSee('10.0.1.26');
});

it('keeps the filter when paging', function () {
    foreach (range(1, 26) as $n) {
        blockRow('10.0.1.'.$n, ['source' => BlockSource::Auto, 'created_at' => now()->subMinutes($n)]);
    }

    signedInAdmin($this)->get('/watchtower?source=auto')
        ->assertOk()
        ->assertSee('source=auto', escape: false);
});

it('loads nothing from the network and runs no JavaScript', function () {
    blockRow('10.0.0.1');

    $html = signedInAdmin($this)->get('/watchtower')->assertOk()->getContent();

    // The whole point of the server-rendered page: it cannot be broken by a
    // CDN outage, needs no build step, and needs no script-src exception.
    expect($html)->not->toContain('<script')
        ->and($html)->not->toContain('<link ')
        ->and($html)->not->toContain('onclick')
        ->and($html)->not->toContain('cdn.')
        ->and($html)->not->toContain('fonts.googleapis.com');
});

it('offers no log entry link when LogScope is not installed', function () {
    blockRow('10.0.0.1', ['log_entry_id' => '01JD8Z1Q0000000000000000AA']);

    signedInAdmin($this)->get('/watchtower')
        ->assertOk()
        ->assertDontSee('View log entry');
});
