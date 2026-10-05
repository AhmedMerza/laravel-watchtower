<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        if ($this->ranFromVendor()) {
            return;
        }

        Schema::table('blacklisted_ips', function (Blueprint $table) {
            // '' means global — a block that applies to the whole app, which is
            // every block that existed before this migration. NOT NULL with a
            // default rather than nullable because MySQL, Postgres and SQLite
            // all treat NULLs as distinct in a unique index: a nullable column
            // would quietly drop the one-row-per-address guarantee below.
            $table->string('scope', 50)->default('')->after('ip');
        });

        // Separate statements: SQLite rebuilds the table for some of these, and
        // mixing a column add with an index change in one blueprint has bitten
        // people on that driver.
        Schema::table('blacklisted_ips', function (Blueprint $table) {
            $table->dropUnique(['ip']);
        });

        Schema::table('blacklisted_ips', function (Blueprint $table) {
            $table->unique(['ip', 'scope']);
        });
    }

    /**
     * ⚠️ This rollback fails if any scoped block exists, because two rows can
     * share an `ip` once they differ by `scope` and the old index cannot hold
     * them both. That is deliberate: dropping the offending rows to make the
     * rollback succeed would delete blocks without telling anyone. Remove the
     * scoped blocks first if you really mean to go back.
     */
    public function down(): void
    {
        if ($this->ranFromVendor()) {
            return;
        }

        Schema::table('blacklisted_ips', function (Blueprint $table) {
            $table->dropUnique(['ip', 'scope']);
        });

        Schema::table('blacklisted_ips', function (Blueprint $table) {
            $table->unique('ip');
        });

        Schema::table('blacklisted_ips', function (Blueprint $table) {
            $table->dropColumn('scope');
        });
    }

    /**
     * Whether this already ran under its undated name — loaded straight from
     * vendor by runsMigrations() before 0.7.0 — so this published, dated
     * copy is the same migration a second time (#128). It then does nothing,
     * up or down: rolling it back must not drop what it never created.
     */
    private function ranFromVendor(): bool
    {
        $table = config('database.migrations');
        $table = is_array($table) ? ($table['table'] ?? 'migrations') : ($table ?? 'migrations');

        return Schema::hasTable($table) && DB::table($table)->where('migration', 'update_blacklisted_ips_table_add_scope')->exists();
    }
};
