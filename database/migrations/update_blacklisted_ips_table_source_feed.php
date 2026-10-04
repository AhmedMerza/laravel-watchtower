<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

/**
 * Adds `feed` to the block source enum, for rows imported from a public
 * blocklist by watchtower:import-feeds (#21).
 *
 * Postgres has no enum column here: Laravel writes `enum()` as a varchar
 * with an inline CHECK, which `->change()` would try to restate inside an
 * ALTER COLUMN TYPE, where Postgres does not accept one. So on Postgres the
 * constraint is swapped directly, under the name Postgres gave it.
 */
return new class extends Migration
{
    public function up(): void
    {
        $this->allow(['manual', 'auto', 'sync', 'feed']);
    }

    public function down(): void
    {
        // Feed rows are re-imported on the next run; the narrower column
        // can't hold them.
        DB::table('blacklisted_ips')->where('source', 'feed')->delete();

        $this->allow(['manual', 'auto', 'sync']);
    }

    /** @param  list<string>  $sources */
    private function allow(array $sources): void
    {
        $connection = Schema::getConnection();

        if ($connection->getDriverName() !== 'pgsql') {
            Schema::table('blacklisted_ips', function (Blueprint $table) use ($sources) {
                $table->enum('source', $sources)->default('manual')->change();
            });

            return;
        }

        $table = $connection->getTablePrefix().'blacklisted_ips';
        $in = implode(', ', array_map(fn ($source) => "'{$source}'", $sources));

        DB::statement("alter table \"{$table}\" drop constraint if exists \"{$table}_source_check\"");
        DB::statement("alter table \"{$table}\" add constraint \"{$table}_source_check\" check (\"source\" in ({$in}))");
    }
};
