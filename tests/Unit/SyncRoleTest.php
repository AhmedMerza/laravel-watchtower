<?php

declare(strict_types=1);

use Watchtower\Enums\SyncRole;

it('reads the role trimmed and case-insensitively', function (mixed $value, ?SyncRole $role, ?string $invalid) {
    config()->set('watchtower.sync.role', $value);

    expect(SyncRole::current())->toBe($role)
        ->and(SyncRole::invalid())->toBe($invalid);
})->with([
    'unset'           => [null, null, null],
    'empty env value' => ['', null, null],
    'whitespace only' => ['   ', null, null],
    'master'          => [' Master ', SyncRole::Master, null],
    'satellite'       => ['SATELLITE', SyncRole::Satellite, null],
    'typo fails shut' => ['primary', SyncRole::Satellite, 'primary'],
]);

it('hints at the routes only for a 404', function () {
    expect(SyncRole::hintFor(404))->toContain('not serving the sync routes')
        ->and(SyncRole::hintFor(401))->toBe('')
        ->and(SyncRole::hintFor(500))->toBe('');
});
