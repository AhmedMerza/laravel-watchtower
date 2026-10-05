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

        Schema::create('blacklisted_ips', function (Blueprint $table) {
            $table->ulid('id')->primary();
            $table->string('ip', 50)->unique();
            $table->text('reason')->nullable();
            $table->string('source_env', 50)->nullable();
            $table->enum('source', ['manual', 'auto', 'sync'])->default('manual');
            $table->timestamp('expires_at')->nullable();
            $table->string('blocked_by', 255)->nullable();
            $table->string('log_entry_id', 26)->nullable(); // ULID ref, NOT a FK
            $table->timestamps();

            $table->index(['ip', 'expires_at']);
        });
    }

    public function down(): void
    {
        if ($this->ranFromVendor()) {
            return;
        }

        Schema::dropIfExists('blacklisted_ips');
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

        return Schema::hasTable($table) && DB::table($table)->where('migration', 'create_blacklisted_ips_table')->exists();
    }
};
