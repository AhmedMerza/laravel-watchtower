<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * The signal log (#138): every signal a real-time detector counted, so
     * detectors can be replayed at other settings later. Off by default —
     * see auto_block.signal_log.
     *
     * One row per counted signal, not per request: a request no detector
     * counts writes nothing. Pruned by `watchtower:cleanup` after
     * retention_days.
     */
    public function up(): void
    {
        Schema::create('watchtower_signals', function (Blueprint $table) {
            $table->id();

            $table->string('detector', 32);

            // The address as the request came in, not the block target: a
            // replay can widen it to its /64, but not narrow it back.
            $table->string('ip', 45);

            // The signed-in user on the request, as the shared-IP guard saw
            // it. Never the account a failed login was aimed at — that is
            // target_user_id.
            $table->string('user_id', 64)->nullable();

            $table->string('path', 255)->nullable();
            $table->unsignedSmallInteger('status')->nullable();

            // failed_logins only: a keyed hash of the identifier typed in,
            // the account it named when one exists, and that account's guard.
            $table->char('target_hash', 64)->nullable();
            $table->string('target_user_id', 64)->nullable();
            $table->string('guard', 32)->nullable();

            $table->timestamp('occurred_at');

            // watchtower:cleanup prunes by age.
            $table->index('occurred_at');

            // A replay reads one detector over a time range.
            $table->index(['detector', 'occurred_at']);
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('watchtower_signals');
    }
};
