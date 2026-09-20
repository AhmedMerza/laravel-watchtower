<?php

declare(strict_types=1);

use Spatie\LaravelPackageTools\Package;
use Watchtower\WatchtowerServiceProvider;

/**
 * The package declares migrations by bare name, with no timestamp prefix.
 *
 * `runsMigrations()` passes each one to `loadMigrationsFrom()`, and Laravel's
 * migrator sorts the files it collects by migration name — it does not run
 * them in the order `configurePackage()` declares. So on any install that
 * doesn't publish migrations, a new migration whose file name sorts before an
 * existing one runs first, against a table that doesn't exist yet.
 *
 * Publishing is unaffected (it stamps them in declaration order), which is
 * exactly why this is easy to miss: it breaks only the installs nobody tests
 * by hand.
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
        'do NOT rename an existing migration, because installs using '.
        'runsMigrations() record the old name and would re-run it.'
    );
});

it('ships a migration file for every name it declares', function () {
    $package = new Package;

    (new WatchtowerServiceProvider($this->app))->configurePackage($package);

    foreach ($package->migrationFileNames as $name) {
        expect(__DIR__."/../../database/migrations/{$name}.php")->toBeFile();
    }
});
