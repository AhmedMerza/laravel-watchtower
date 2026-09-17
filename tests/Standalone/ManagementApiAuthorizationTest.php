<?php

declare(strict_types=1);

use Illuminate\Auth\GenericUser;
use Illuminate\Foundation\Auth\User;
use Illuminate\Foundation\Http\Middleware\ValidateCsrfToken;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Gate;
use Illuminate\Support\Facades\Queue;
use Illuminate\Support\Facades\Route;
use Watchtower\Enums\BlockSource;
use Watchtower\Http\Middleware\Authorize;
use Watchtower\Models\BlacklistedIp;
use Watchtower\Tests\StandaloneServiceProvider;

beforeEach(function () {
    Event::fake();
    Queue::fake();

    // An existing block, so a refused DELETE can be seen to change nothing.
    BlacklistedIp::create([
        'ip'         => '10.0.0.1',
        'source'     => BlockSource::Manual,
        'source_env' => 'testing',
    ]);
});

dataset('management endpoints', [
    'list'    => ['GET', '/watchtower/api/blocks'],
    'status'  => ['GET', '/watchtower/api/status/10.0.0.1'],
    'block'   => ['POST', '/watchtower/api/block'],
    'unblock' => ['DELETE', '/watchtower/api/block/10.0.0.1'],
]);

function eloquentUser(string $email): User
{
    return (new User)->forceFill(['id' => 1, 'email' => $email]);
}

function allowAdminOnly(): void
{
    Gate::define('viewWatchtower', fn ($user) => $user->email === 'admin@example.com');
}

it('mounts the API at its own prefix behind the Gate check', function () {
    $route = Route::getRoutes()->getByName('watchtower.api.blocks');

    expect($route->uri())->toBe('watchtower/api/blocks')
        ->and($route->gatherMiddleware())->toBe(['web', Authorize::class]);
});

it('refuses an anonymous request outside local', function (string $method, string $uri) {
    $this->json($method, $uri, ['ip' => '10.0.0.2'])
        ->assertForbidden()
        ->assertJsonPath('message', 'Unauthorized access to Watchtower.');

    expect(BlacklistedIp::pluck('ip')->all())->toBe(['10.0.0.1']);
})->with('management endpoints');

it('refuses a browser request with a 403 rather than a redirect', function () {
    $this->get('/watchtower/api/blocks')->assertForbidden();
});

it('lets an anonymous request through in local', function (string $method, string $uri) {
    $this->app['env'] = 'local';

    // Laravel skips the CSRF check only in `testing`, and this is a gate test.
    $this->withoutMiddleware(ValidateCsrfToken::class)
        ->json($method, $uri, ['ip' => '10.0.0.2'])
        ->assertOk();
})->with('management endpoints');

it('grants access to a user the app\'s Gate allows', function (string $method, string $uri) {
    allowAdminOnly();

    $this->actingAs(eloquentUser('admin@example.com'))
        ->json($method, $uri, ['ip' => '10.0.0.2'])
        ->assertOk();
})->with('management endpoints');

it('refuses a user the app\'s Gate does not allow', function () {
    allowAdminOnly();

    $this->actingAs(eloquentUser('someone@example.com'))
        ->getJson('/watchtower/api/blocks')
        ->assertForbidden();
});

it('refuses a guest once the app\'s Gate needs a user, even in local', function () {
    allowAdminOnly();
    $this->app['env'] = 'local';

    $this->getJson('/watchtower/api/blocks')->assertForbidden();
});

it('keeps a Gate the app defined before Watchtower did', function () {
    Gate::define('viewWatchtower', fn ($user = null) => true);

    $this->app->getProvider(StandaloneServiceProvider::class)->redefineGate();

    $this->getJson('/watchtower/api/blocks')->assertOk();
});

it('keeps the Gate check when routes.middleware is emptied', function () {
    config()->set('watchtower.routes.middleware', []);
    $this->app->getProvider(StandaloneServiceProvider::class)->reregisterRoutes();

    expect(Route::getRoutes()->getByName('watchtower.api.blocks')->gatherMiddleware())->toBe([Authorize::class]);

    $this->getJson('/watchtower/api/blocks')->assertForbidden();
});

it('still needs the Gate when routes.middleware requires a login', function () {
    config()->set('watchtower.routes.middleware', ['web', 'auth']);
    $this->app->getProvider(StandaloneServiceProvider::class)->reregisterRoutes();

    $this->actingAs(eloquentUser('someone@example.com'))
        ->getJson('/watchtower/api/blocks')
        ->assertForbidden();
});
