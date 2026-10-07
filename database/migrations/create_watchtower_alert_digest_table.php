<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * The day's alerts, waiting for `watchtower:alert-digest` (#124).
     *
     * A table rather than the cache: deploy scripts commonly run
     * `cache:clear`, which would empty the day's digest without a trace. And
     * not a query of `blacklisted_ips` at send time: an expired or unblocked
     * block is deleted from there long before the evening, and a near miss
     * was never stored at all.
     *
     * One row per address and reason, counting its repeats, not one per
     * event: a near miss behind a shared gateway can fire on every request,
     * and the table must grow with addresses, not traffic.
     */
    public function up(): void
    {
        Schema::create('watchtower_alert_digest', function (Blueprint $table) {
            $table->id();

            // blocked | would_have_blocked
            $table->string('type', 20);

            // The block target, so an IPv6 near miss groups under its /64
            // the way the block would.
            $table->string('ip', 50);

            // '' means global, as in blacklisted_ips.scope.
            $table->string('scope', 50)->default('');

            $table->text('reason');
            $table->string('not_blocked_because', 100)->nullable();

            $table->unsignedInteger('events')->default(1);

            // How many of those the throttle or cap kept from alerting at
            // the time.
            $table->unsignedInteger('held_back')->default(0);

            // Claimed by a digest that is sending. Repeats after that start a
            // new row, so nothing that happens mid-send is deleted with it.
            $table->boolean('sealed')->default(false);

            $table->timestamp('first_at')->nullable();
            $table->timestamp('last_at')->nullable();

            // The listener finds an address's open row by these.
            $table->index(['ip', 'type']);

            // watchtower:cleanup drops rows no digest ever took.
            $table->index('last_at');
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('watchtower_alert_digest');
    }
};
