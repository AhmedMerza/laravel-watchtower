<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * The offence ledger: how many times each address has earned an
     * auto-block, so a repeat offender can be given a longer one.
     *
     * Deliberately NOT a column on `blacklisted_ips`. `watchtower:cleanup`
     * deletes a block row once it expires, which is exactly the moment the
     * count becomes interesting — an offender who comes back after their
     * first block lapsed is the whole case escalation exists for, and a
     * counter living on the deleted row would always read zero for them.
     */
    public function up(): void
    {
        if ($this->ranFromVendor()) {
            return;
        }

        Schema::create('ip_offences', function (Blueprint $table) {
            $table->ulid('id')->primary();
            $table->string('ip', 50);

            // '' means global, matching blacklisted_ips.scope — and NOT NULL
            // with a default for the same reason that table gives: every
            // driver treats NULLs as distinct in a unique index, so a
            // nullable column would quietly drop the guarantee below.
            $table->string('scope', 50)->default('');

            $table->unsignedInteger('offence_count')->default(0);

            // When this ladder started, kept for the operator reading the
            // table — "three offences since March" answers a different
            // question from "three offences". Replaces created_at, which
            // would otherwise say the same thing under a vaguer name.
            $table->timestamp('first_offence_at')->nullable();
            $table->timestamp('last_offence_at')->nullable();

            // One ledger per address per scope, mirroring the (ip, scope)
            // unique index blocks themselves use.
            $table->unique(['ip', 'scope']);

            // watchtower:cleanup prunes by age on every run.
            $table->index('last_offence_at');
        });
    }

    public function down(): void
    {
        if ($this->ranFromVendor()) {
            return;
        }

        Schema::dropIfExists('ip_offences');
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

        return Schema::hasTable($table) && DB::table($table)->where('migration', 'create_ip_offences_table')->exists();
    }
};
