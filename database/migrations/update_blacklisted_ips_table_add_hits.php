<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::table('blacklisted_ips', function (Blueprint $table) {
            $table->unsignedInteger('hits')->default(0)->after('log_entry_id');
            $table->timestamp('last_hit_at')->nullable()->after('hits');
        });
    }

    public function down(): void
    {
        Schema::table('blacklisted_ips', function (Blueprint $table) {
            $table->dropColumn(['hits', 'last_hit_at']);
        });
    }
};
