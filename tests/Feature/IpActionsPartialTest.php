<?php

declare(strict_types=1);

use Illuminate\Http\Request;
use Illuminate\Routing\RouteCollection;
use Illuminate\Support\Facades\Route;
use LogScope\LogScopeServiceProvider;

/**
 * The Block IP button builds its URLs client-side, so the API tests hitting
 * /logscope/watchtower/api/* all passed while the partial was posting to a
 * path that didn't exist (#11). These tests read the URLs the rendered
 * partial actually embeds and put them through the router.
 */
function renderIpActions(): string
{
    return view('watchtower::partials.ip-actions')->render();
}

/**
 * Pulls the URL map back out of the `x-data` attribute. Blade's @js renders it
 * as JSON.parse('…'), so there are two layers: the JS string literal, then the
 * JSON inside it.
 */
function embeddedIpActionUrls(string $html): array
{
    expect($html)->toMatch("/watchtowerIpActions\(JSON\.parse\('/");

    preg_match("/watchtowerIpActions\(JSON\.parse\('(.*?)'\)\)/", $html, $matches);

    return json_decode(json_decode('"'.($matches[1] ?? '').'"'), true) ?? [];
}

beforeEach(function () {
    config()->set('watchtower.enabled', true);
});

it('embeds URLs that resolve to the registered API routes', function () {
    $urls = embeddedIpActionUrls(renderIpActions());

    expect($urls)->toHaveKeys(['block', 'unblock', 'status']);

    // match() throws NotFoundHttpException / MethodNotAllowedHttpException
    // when the URL or verb misses, which is exactly the #11 failure.
    $matched = [
        Route::getRoutes()->match(Request::create($urls['block'], 'POST')),
        Route::getRoutes()->match(Request::create(str_replace('__IP__', '10.0.0.1', $urls['unblock']), 'DELETE')),
        Route::getRoutes()->match(Request::create(str_replace('__IP__', '10.0.0.1', $urls['status']), 'GET')),
    ];

    expect(array_map(fn ($route) => $route->getName(), $matched))
        ->toBe(['watchtower.api.block', 'watchtower.api.unblock', 'watchtower.api.status']);
});

it('keeps the IP placeholder on the routes that take one', function () {
    $urls = embeddedIpActionUrls(renderIpActions());

    expect($urls['unblock'])->toContain('__IP__')
        ->and($urls['status'])->toContain('__IP__')
        ->and($urls['block'])->not->toContain('__IP__');
});

it('renders nothing when the API routes are not registered', function () {
    // e.g. WATCHTOWER_ROUTES_ENABLED=false — the button has nothing to call,
    // and route() would throw inside LogScope's detail panel.
    Route::setRoutes(new RouteCollection);

    expect(trim(renderIpActions()))->toBe('');
});

it('renders nothing when Watchtower is disabled', function () {
    config()->set('watchtower.enabled', false);

    expect(trim(renderIpActions()))->toBe('');
});

it('leaves no pre-rename guard identifiers in the markup', function () {
    expect(renderIpActions())->not->toMatch('/guard/i');
});

it('reaches the same routes when LogScope renders its own detail panel', function () {
    // The partial only ever appears via LogScope's @includeIf, so render the
    // real panel: this covers the include itself, not just our view in
    // isolation. LogScope is a dev dependency, so its provider isn't in the
    // test app's provider list by default.
    $this->app->register(LogScopeServiceProvider::class);

    $urls = embeddedIpActionUrls(view('logscope::partials.detail-panel')->render());

    expect(Route::getRoutes()->match(Request::create($urls['block'], 'POST'))->getName())
        ->toBe('watchtower.api.block');
});
