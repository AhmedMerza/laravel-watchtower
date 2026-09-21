<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Route;
use Watchtower\Tests\TestCase;

// `ui.enabled` is read once, when the routes are registered at boot, so it
// has to be set before the app comes up — which is what $beforeBoot does and
// a beforeEach() cannot. Hence a file of its own.
beforeAll(function () {
    TestCase::$beforeBoot = function ($app) {
        $app['config']->set('watchtower.ui.enabled', false);
    };
});

afterAll(function () {
    TestCase::$beforeBoot = null;
});

it('drops the page but keeps the API', function () {
    expect(Route::getRoutes()->getByName('watchtower.ui.index'))->toBeNull()
        ->and(Route::getRoutes()->getByName('watchtower.api.blocks'))->not->toBeNull();
});

it('serves nothing at the prefix', function () {
    $this->app['env'] = 'local';

    $this->get('/watchtower')->assertNotFound();
});
