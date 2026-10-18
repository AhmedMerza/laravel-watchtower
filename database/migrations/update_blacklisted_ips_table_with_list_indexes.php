<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * Indexes for the block list the management page and GET /blocks page
 * through (#65). Feed import (#21) puts tens of thousands of rows in this
 * table, and the list sorted all of them on every page load.
 *
 * Measured on 50k rows (mostly feed) on SQLite, MySQL 8 and Postgres 16:
 *
 * - (created_at, id) matches latestFirst()'s order, so a page is an index
 *   walk that stops after 25 matches instead of a scan and filesort —
 *   15–96ms down to 0.1–1ms.
 * - That walk is only cheap while matches are common near the newest end.
 *   When they are rare it reads most of the index, and on MySQL it was
 *   slower than no index at all (222ms against 48ms, expired view with
 *   17 expired rows). expires_at gives the expired view a direct route, and
 *   (source, created_at) does the same for the source filter, where
 *   `manual` is a sliver of a feed-sized table.
 *
 * All three together cost nothing measurable on single inserts and about
 * 0.1s per 5,000 rows on batch inserts.
 *
 * Not indexed, on purpose: the scope = '' filter in reconcile and the sync
 * pull (#108). Nearly every row is global, so an index on scope selects
 * almost everything, and `source != 'feed'` cannot use an index as a range.
 * The paged pull already runs on the primary key.
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::table('blacklisted_ips', function (Blueprint $table) {
            $table->index(['created_at', 'id']);
            $table->index(['source', 'created_at']);
            $table->index('expires_at');
        });
    }

    public function down(): void
    {
        Schema::table('blacklisted_ips', function (Blueprint $table) {
            $table->dropIndex(['created_at', 'id']);
            $table->dropIndex(['source', 'created_at']);
            $table->dropIndex(['expires_at']);
        });
    }
};
