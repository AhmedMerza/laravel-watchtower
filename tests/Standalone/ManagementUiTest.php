<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Queue;
use Illuminate\Support\Facades\Route;
use Watchtower\Enums\BlockSource;
use Watchtower\Enums\BlockState;
use Watchtower\Http\Middleware\Authorize;
use Watchtower\Models\BlacklistedIp;
use Watchtower\Services\AutoBlockService;
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

/**
 * forceCreate, not create: `created_at` is not in the model's $fillable, so
 * create() drops it silently and every row in a loop lands on the same
 * second — which left the pagination test below ordering on a full tie and
 * passing only because SQLite happened to return insertion order.
 */
function blockRow(string $ip, array $attributes = []): BlacklistedIp
{
    return BlacklistedIp::forceCreate(array_merge([
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
    ])->assertRedirect()
        ->assertSessionHas('watchtower_status', 'Blocked 203.0.113.0/24 from the auth routes.');

    expect(BlacklistedIp::firstWhere('ip', '203.0.113.0/24')->scope)->toBe('auth');
});

it('reports the network it stored for a single IPv6 address', function () {
    uiPost(signedInAdmin($this), '/watchtower/block', [
        'ip'       => '2001:db8::5',
        'duration' => '1h',
    ])->assertRedirect();

    $block = BlacklistedIp::sole();

    // An operator who blocks one IPv6 address needs to see that the /64
    // around it was blocked, so the message names the stored target.
    expect($block->ip)->toContain('/64')
        ->and($block->ip)->not->toBe('2001:db8::5')
        ->and(session('watchtower_status'))->toBe("Blocked {$block->ip}.");
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

    // The exception's own message, not a generic "invalid": the operator has
    // to be able to tell "that address is protected" from "you typed it wrong".
    uiPost(signedInAdmin($this), '/watchtower/block', [
        'ip'       => '127.0.0.1',
        'duration' => '1h',
    ])->assertSessionHasErrors([
        'ip' => '127.0.0.1 is in the never-block whitelist and cannot be blocked.',
    ]);

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

it('can still lift a block whose scope is no longer declared', function () {
    $block = blockRow('10.0.0.1', ['scope' => 'auth']);

    // The scope is retired from config while its rows are still in the table.
    // BlockScope::normalize() throws on a name it no longer knows, which
    // would 500 the one page that can clear those rows.
    config()->set('watchtower.scopes', []);

    uiPost(signedInAdmin($this), '/watchtower/unblock', ['id' => $block->id])
        ->assertRedirect()
        ->assertSessionHas('watchtower_status', 'Unblocked 10.0.0.1.');

    expect(BlacklistedIp::count())->toBe(0);
});

it('hides the scope selector and still blocks when no scopes are declared', function () {
    config()->set('watchtower.scopes', []);

    signedInAdmin($this)->get('/watchtower')
        ->assertOk()
        ->assertDontSee('Applies to');

    uiPost(signedInAdmin($this), '/watchtower/block', [
        'ip'       => '203.0.113.9',
        'duration' => '1h',
    ])->assertRedirect();

    expect(BlacklistedIp::firstWhere('ip', '203.0.113.9')->scope)->toBe(BlockScope::GLOBAL);
});

it('sends every redirect to the list, never to the Referer the request carried', function () {
    // back() prefers the Referer header over the session's previous URL and
    // does not require it to point at this app. All three paths are covered
    // deliberately: an earlier version of this test only exercised the block
    // success path, which returns its own redirect and would have passed
    // whatever the other two did.
    $block = blockRow('10.0.0.1');
    $evil = 'https://evil.example/anywhere';

    uiPost(signedInAdmin($this)->withHeader('referer', $evil), '/watchtower/block', [
        'ip' => '203.0.113.7', 'duration' => '1h',
    ])->assertRedirect(route('watchtower.ui.index'));

    uiPost(signedInAdmin($this)->withHeader('referer', $evil), '/watchtower/block', [
        'ip' => 'not-an-ip', 'duration' => '1h',
    ])->assertRedirect(route('watchtower.ui.index'));

    uiPost(signedInAdmin($this)->withHeader('referer', $evil), '/watchtower/unblock', [
        'id' => $block->id,
    ])->assertRedirect(route('watchtower.ui.index'));
});

it('comes back to the filter and page the unblock was made from', function () {
    $block = blockRow('10.0.0.1', ['source' => BlockSource::Auto]);

    uiPost(signedInAdmin($this), '/watchtower/unblock', [
        'id'     => $block->id,
        'source' => 'auto',
        'state'  => 'all',
        'page'   => '2',
    ])->assertRedirect(route('watchtower.ui.index', ['source' => 'auto', 'state' => 'all', 'page' => 2]));
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

// The options come from BlockState, so a new case reaches the page without a
// template edit — and the one the list is showing stays selected (#81).
it('offers every state in the Showing select, with the current one selected', function () {
    $html = signedInAdmin($this)->get('/watchtower?state=expired')->assertOk()->getContent();

    foreach (BlockState::cases() as $case) {
        $selected = $case === BlockState::Expired ? 'selected' : '';

        expect($html)->toMatch('#<option value="'.$case->value.'"\s*'.$selected.'>'.$case->label().'</option>#');
    }
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

    $response = signedInAdmin($this)->get('/watchtower')->assertOk();

    // A positive assertion first: every check below is a not->toContain, and
    // they would all pass against an empty 200 from a broken view.
    $response->assertSee('10.0.0.1')->assertSee('<table', escape: false);

    $html = $response->getContent();

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

/**
 * failed_logins armed in block mode, one failure to trip it, on a cache that
 * the override and the hit counters share.
 */
function armFailedLogins(): void
{
    config()->set('cache.default', 'array');
    config()->set('watchtower.cache.store', 'array');
    Cache::flush();
    config()->set('watchtower.auto_block.enabled', true);
    config()->set('watchtower.auto_block.mode', 'warn');
    config()->set('watchtower.auto_block.detectors.failed_logins.enabled', true);
    config()->set('watchtower.auto_block.detectors.failed_logins.mode', 'block');
    config()->set('watchtower.auto_block.detectors.failed_logins.count', 1);
}

it('shows each detector with its mode, threshold and scope', function () {
    armFailedLogins();

    signedInAdmin($this)->get('/watchtower')
        ->assertOk()
        ->assertSee('failed_logins')
        ->assertSee('bad_user_agent')
        ->assertSee('1 in 5 min')
        ->assertSee('?warn=failed_logins', false);
});

it('switches a blocking detector to warn, and the detector then only warns', function () {
    armFailedLogins();

    uiPost(signedInAdmin($this), '/watchtower/detectors/warn', ['detector' => 'failed_logins'])
        ->assertRedirect('/watchtower')
        ->assertSessionHas('watchtower_status', 'Switched failed_logins to warn. It stays in warn until its config changes.');

    $mode = app(AutoBlockService::class)->detectorMode('failed_logins');

    expect($mode['mode'])->toBe('warn')
        ->and($mode['configured'])->toBe('block')
        ->and($mode['override']['by'])->toBe('admin@example.com');

    app(AutoBlockService::class)->record('failed_logins', '203.0.113.7');

    expect(BlacklistedIp::count())->toBe(0);

    $this->get('/watchtower')->assertSee('switched from block by admin@example.com');
});

it('re-arms the detector when its config changes, not from the page', function () {
    armFailedLogins();

    uiPost(signedInAdmin($this), '/watchtower/detectors/warn', ['detector' => 'failed_logins']);

    config()->set('watchtower.auto_block.detectors.failed_logins.count', 2);

    expect(app(AutoBlockService::class)->detectorMode('failed_logins'))
        ->toMatchArray(['mode' => 'block', 'override' => null]);
});

it('blocks normally when nobody switched the detector', function () {
    armFailedLogins();

    app(AutoBlockService::class)->record('failed_logins', '203.0.113.7');

    expect(BlacklistedIp::count())->toBe(1);
});

it('has nothing to switch on a detector that does not block', function () {
    armFailedLogins();
    config()->set('watchtower.auto_block.detectors.failed_logins.mode', 'disabled');

    uiPost(signedInAdmin($this), '/watchtower/detectors/warn', ['detector' => 'failed_logins'])
        ->assertSessionHas('watchtower_status', "failed_logins isn't blocking, so there was nothing to switch.");

    config()->set('watchtower.auto_block.detectors.failed_logins.mode', 'block');

    expect(app(AutoBlockService::class)->detectorMode('failed_logins')['override'])->toBeNull();
});

it('refuses a detector that is not configured', function () {
    armFailedLogins();

    uiPost(signedInAdmin($this), '/watchtower/detectors/warn', ['detector' => 'nope'])
        ->assertSessionHasErrors('detector');
});

it('still lists blocks when the cache store does not answer', function () {
    armFailedLogins();
    blockRow('198.51.100.1');
    config()->set('watchtower.cache.store', 'no-such-store');

    signedInAdmin($this)->get('/watchtower')
        ->assertOk()
        ->assertSee('198.51.100.1')
        ->assertSee("Couldn't read the detectors' state", false);
});

it('drops the switch when the global mode changes', function () {
    armFailedLogins();
    app(AutoBlockService::class)->switchToWarn('failed_logins', 'admin@example.com');

    config()->set('watchtower.auto_block.mode', 'block');

    expect(app(AutoBlockService::class)->detectorMode('failed_logins'))
        ->toMatchArray(['mode' => 'block', 'override' => null]);
});

it('does not bring a spent switch back when the old config is restored', function () {
    armFailedLogins();
    app(AutoBlockService::class)->switchToWarn('failed_logins', 'admin@example.com');

    // Re-armed in config, read once under the new config, then reverted.
    config()->set('watchtower.auto_block.detectors.failed_logins.count', 5);
    app(AutoBlockService::class)->detectorMode('failed_logins');
    config()->set('watchtower.auto_block.detectors.failed_logins.count', 1);

    expect(app(AutoBlockService::class)->detectorMode('failed_logins')['override'])->toBeNull();
});

it('retires a switch whose detector was moved to warn in config, so moving it back to block re-arms it', function () {
    armFailedLogins();
    app(AutoBlockService::class)->switchToWarn('failed_logins', 'admin@example.com');

    config()->set('watchtower.auto_block.detectors.failed_logins.mode', 'warn');
    app(AutoBlockService::class)->detectorMode('failed_logins');
    config()->set('watchtower.auto_block.detectors.failed_logins.mode', 'block');

    expect(app(AutoBlockService::class)->detectorMode('failed_logins')['mode'])->toBe('block');
});

it('asks before switching, and only on the row it was asked for', function () {
    armFailedLogins();
    config()->set('watchtower.auto_block.detectors.scanner_paths.enabled', true);
    config()->set('watchtower.auto_block.detectors.scanner_paths.mode', 'block');

    signedInAdmin($this)->get('/watchtower?warn=failed_logins')
        ->assertOk()
        ->assertSee('action="'.route('watchtower.ui.detectors.warn').'"', false)
        ->assertSee('name="detector" value="failed_logins"', false)
        ->assertDontSee('name="detector" value="scanner_paths"', false)
        ->assertSee('?warn=scanner_paths', false)
        ->assertSee('Cancel');
});

it('offers no switch on a detector that is not blocking, even when asked', function () {
    armFailedLogins();
    config()->set('watchtower.auto_block.detectors.failed_logins.mode', 'warn');

    signedInAdmin($this)->get('/watchtower?warn=failed_logins')
        ->assertOk()
        ->assertDontSee('name="detector"', false);
});

it('refuses the switch to a user the app\'s Gate does not allow', function () {
    armFailedLogins();
    allowAdminOnly();

    uiPost($this->actingAs(eloquentUser('someone@example.com')), '/watchtower/detectors/warn', ['detector' => 'failed_logins'])
        ->assertForbidden();

    expect(app(AutoBlockService::class)->detectorMode('failed_logins')['override'])->toBeNull();
});

it('logs who switched a detector', function () {
    armFailedLogins();
    Log::shouldReceive('channel')->once()->andReturnSelf();
    Log::shouldReceive('warning')->once()->with(
        'Watchtower: detector switched to warn from the management page',
        ['detector' => 'failed_logins', 'by' => 'admin@example.com'],
    );

    expect(app(AutoBlockService::class)->switchToWarn('failed_logins', 'admin@example.com'))->toBeTrue();
});

it('keeps the first switch when the button is pressed again', function () {
    armFailedLogins();
    $this->travelTo(now()->subHour());
    app(AutoBlockService::class)->switchToWarn('failed_logins', 'first@example.com');
    $this->travelBack();

    uiPost(signedInAdmin($this), '/watchtower/detectors/warn', ['detector' => 'failed_logins'])
        ->assertSessionHas('watchtower_status', "failed_logins isn't blocking, so there was nothing to switch.");

    expect(app(AutoBlockService::class)->detectorMode('failed_logins')['override'])
        ->toMatchArray(['by' => 'first@example.com', 'at' => now()->subHour()->getTimestamp()]);
});

it('says so instead of failing when the cache store is down at the switch', function () {
    armFailedLogins();
    config()->set('watchtower.cache.store', 'no-such-store');

    uiPost(signedInAdmin($this), '/watchtower/detectors/warn', ['detector' => 'failed_logins'])
        ->assertRedirect('/watchtower')
        ->assertSessionHasErrors('detector');
});

it('shows a switch whose cached time is unreadable without failing the page', function () {
    armFailedLogins();
    app(AutoBlockService::class)->switchToWarn('failed_logins', 'admin@example.com');
    $key = 'watchtower:blacklist:detector_warn:failed_logins';
    Cache::store('array')->forever($key, ['at' => 'not a time'] + Cache::store('array')->get($key));

    signedInAdmin($this)->get('/watchtower')
        ->assertOk()
        ->assertSee('switched from block by admin@example.com');
});

it('has nothing to switch on a detector that is not running', function (string $off) {
    armFailedLogins();
    config()->set($off, false);

    expect(app(AutoBlockService::class)->switchToWarn('failed_logins', 'admin@example.com'))->toBeFalse()
        ->and(Cache::store('array')->get('watchtower:blacklist:detector_warn:failed_logins'))->toBeNull();
})->with([
    'detector off'   => 'watchtower.auto_block.detectors.failed_logins.enabled',
    'auto-block off' => 'watchtower.auto_block.enabled',
]);
