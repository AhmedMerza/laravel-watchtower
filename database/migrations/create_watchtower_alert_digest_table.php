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
     * One row per event. The digest groups them when it sends, and deletes
     * the rows it sent.
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

            // Whether the instant alert went out for this event, so the
            // digest can say what the throttle or cap held back.
            $table->boolean('sent')->default(false);

            $table->timestamp('created_at')->nullable();
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('watchtower_alert_digest');
    }
};
