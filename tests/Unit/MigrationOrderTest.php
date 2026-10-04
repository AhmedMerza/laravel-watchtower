<?php

declare(strict_types=1);

use Spatie\LaravelPackageTools\Package;
use Watchtower\WatchtowerServiceProvider;

/**
 * The package declares migrations by bare name, with no timestamp prefix.
 * Publishing is the only way they ever run (#104), and spatie/package-tools
 * stamps each one with an incrementing timestamp in the order
 * `configurePackage()` declares them — not the order their file names sort
 * into. Keeping the two in sync is just readability now, but older installs
 * from before #104 may still have one of these recorded under its bare name
 * via the removed `runsMigrations()` load path, which is why renaming an
 * existing migration is still off-limits.
 */
it('declares migrations in the order their file names sort', function () {
    $package = new Package;

    (new WatchtowerServiceProvider($this->app))->configurePackage($package);

    $declared = $package->migrationFileNames;
    $sorted = collect($declared)->sort()->values()->all();

    expect($declared)->toBe(
        $sorted,
        'Migration file names must sort into the order they have to run. '.
        'Rename the new migration so it sorts after the one it depends on — '.
        'do NOT rename an existing migration, because installs from before '.
        '#104 may still have it recorded under its old, bare name.'
    );
});

it('ships a migration file for every name it declares', function () {
    $package = new Package;

    (new WatchtowerServiceProvider($this->app))->configurePackage($package);

    foreach ($package->migrationFileNames as $name) {
        expect(__DIR__."/../../database/migrations/{$name}.php")->toBeFile();
    }
});

it('declares every migration it ships', function () {
    // A migration that is shipped but never declared is never published, and
    // publishing is the only way one runs (#104) — so an upgraded app simply
    // never gets it. The hits columns (#20) went out exactly like that.
    $package = new Package;

    (new WatchtowerServiceProvider($this->app))->configurePackage($package);

    $shipped = collect(glob(__DIR__.'/../../database/migrations/*.php'))
        ->map(fn ($path) => basename($path, '.php'))
        ->sort()->values()->all();

    expect(collect($package->migrationFileNames)->sort()->values()->all())->toBe($shipped);
});
