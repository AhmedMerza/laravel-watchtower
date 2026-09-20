<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Route;
use Watchtower\Exceptions\UnknownScopeException;
use Watchtower\Support\BlockScope;

beforeEach(function () {
    config()->set('watchtower.scopes', ['auth', 'admin']);
});

it('normalizes a blank scope to global', function (?string $given) {
    expect(BlockScope::normalize($given))->toBe(BlockScope::GLOBAL);
})->with([null, '', '  ']);

it('accepts a declared scope, trimmed', function () {
    expect(BlockScope::normalize(' auth '))->toBe('auth');
});

it('refuses a scope the config does not declare', function () {
    expect(fn () => BlockScope::normalize('atuh'))
        ->toThrow(UnknownScopeException::class);
});

it('names the declared scopes in the refusal, so the typo is obvious', function () {
    expect(fn () => BlockScope::normalize('atuh'))
        ->toThrow(UnknownScopeException::class, 'Declared scopes: auth, admin.');
});

it('drops blanks and duplicates from the declared list', function () {
    config()->set('watchtower.scopes', ['auth', '', 'auth', '  ', 'admin']);

    expect(BlockScope::declared())->toBe(['auth', 'admin']);
});

it('counts the routes carrying each scope', function () {
    Route::get('/login', fn () => 'ok')->middleware('watchtower:auth');
    Route::post('/login', fn () => 'ok')->middleware('watchtower:auth');
    Route::get('/panel', fn () => 'ok')->middleware('watchtower:admin');
    Route::get('/open', fn () => 'ok');

    expect(BlockScope::routeCounts())->toBe(['auth' => 2, 'admin' => 1]);
});

it('counts a route naming several scopes towards each of them', function () {
    Route::get('/panel', fn () => 'ok')->middleware('watchtower:auth,admin');

    expect(BlockScope::routeCounts())->toBe(['auth' => 1, 'admin' => 1]);
});

it('reports nothing for a declared scope no route carries', function () {
    // This is what watchtower:install warns about: the block would be stored,
    // reported as a block, and enforce nothing.
    Route::get('/login', fn () => 'ok')->middleware('watchtower:auth');

    expect(BlockScope::routeCounts())->not->toHaveKey('admin');
});
