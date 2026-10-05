<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\File;
use Illuminate\Support\Facades\Schema;

/*
 * An install from before 0.7.0 that never published its migrations: they ran
 * from vendor through runsMigrations(), and Laravel recorded them under their
 * undated names (#128). This is oreem's production state, exactly:
 *
 *   create_blacklisted_ips_table, create_ip_offences_table,
 *   update_blacklisted_ips_table_add_scope — and nothing after.
 */
beforeEach(function () {
    Schema::dropIfExists('blacklisted_ips');
    Schema::dropIfExists('ip_offences');

    $repository = app('migration.repository');
    if (! $repository->repositoryExists()) {
        $repository->createRepository();
    }

    foreach (['create_blacklisted_ips_table', 'create_ip_offences_table', 'update_blacklisted_ips_table_add_scope'] as $name) {
        (include __DIR__."/../../database/migrations/{$name}.php")->up();
        $repository->log($name, 303);
    }

    DB::table('blacklisted_ips')->insert([
        'id' => '01J00000000000000000000000', 'ip' => '45.9.20.5', 'scope' => '',
        'source' => 'manual', 'created_at' => now(), 'updated_at' => now(),
    ]);

    // What `vendor:publish --tag=watchtower-migrations` writes: every
    // migration, under a dated name, in the provider's order.
    $this->published = sys_get_temp_dir().'/watchtower-published-'.uniqid();
    File::makeDirectory($this->published);

    foreach ([
        'create_blacklisted_ips_table', 'create_ip_offences_table', 'update_blacklisted_ips_table_add_hits',
        'update_blacklisted_ips_table_add_scope', 'update_blacklisted_ips_table_source_feed',
    ] as $i => $name) {
        File::copy(__DIR__."/../../database/migrations/{$name}.php", sprintf('%s/2026_10_05_00000%d_%s.php', $this->published, $i, $name));
    }
});

afterEach(fn () => File::deleteDirectory($this->published));

it('publishes and migrates over a vendor-run install, keeping its data', function () {
    expect(Artisan::call('migrate', ['--path' => $this->published, '--realpath' => true]))->toBe(0);

    expect(DB::table('blacklisted_ips')->pluck('ip')->all())->toBe(['45.9.20.5'])
        ->and(Schema::hasColumns('blacklisted_ips', ['hits', 'last_hit_at', 'scope']))->toBeTrue();

    // The source column takes the value the feed migration added.
    DB::table('blacklisted_ips')->insert([
        'id' => '01J00000000000000000000001', 'ip' => '45.9.20.6', 'scope' => '',
        'source' => 'feed', 'created_at' => now(), 'updated_at' => now(),
    ]);
    expect(DB::table('blacklisted_ips')->count())->toBe(2);
});

it('rolls the published copies back without dropping what they never created', function () {
    Artisan::call('migrate', ['--path' => $this->published, '--realpath' => true]);

    expect(Artisan::call('migrate:rollback', ['--path' => $this->published, '--realpath' => true]))->toBe(0);

    expect(Schema::hasTable('ip_offences'))->toBeTrue()
        ->and(DB::table('blacklisted_ips')->pluck('ip')->all())->toBe(['45.9.20.5'])
        ->and(Schema::hasColumn('blacklisted_ips', 'scope'))->toBeTrue()
        // What the published copies really did is undone.
        ->and(Schema::hasColumn('blacklisted_ips', 'hits'))->toBeFalse();
});

it('still creates everything on a fresh install', function () {
    Schema::dropIfExists('blacklisted_ips');
    Schema::dropIfExists('ip_offences');
    DB::table('migrations')->delete();

    expect(Artisan::call('migrate', ['--path' => $this->published, '--realpath' => true]))->toBe(0)
        ->and(Schema::hasColumns('blacklisted_ips', ['scope', 'hits']))->toBeTrue()
        ->and(Schema::hasTable('ip_offences'))->toBeTrue();
});
