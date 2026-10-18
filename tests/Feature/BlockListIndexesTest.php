<?php

declare(strict_types=1);

use Illuminate\Support\Facades\DB;
use Watchtower\Models\BlacklistedIp;

/*
 * The block list sorts on latestFirst() (#65). Without an index in that exact
 * column order SQLite plans a temp B-tree for the ORDER BY — the filesort the
 * list paid on every page load. Asserting on the plan, not the index's
 * existence, also catches latestFirst() drifting away from the index.
 *
 * This guards the sort only. (source, created_at) and expires_at pay off when
 * a filter matches few rows of a large table, which an empty SQLite table
 * can't show — the planner walks (created_at, id) for every case here.
 */
function planFor($query): string
{
    $rows = DB::select('explain query plan '.$query->toSql(), $query->getBindings());

    return collect($rows)->pluck('detail')->implode("\n");
}

it('pages the block list off an index instead of sorting the table', function (?string $source, string $state) {
    $plan = planFor(BlacklistedIp::filter($source, $state)->latestFirst()->limit(25));

    expect($plan)->not->toContain('TEMP B-TREE FOR ORDER BY')
        ->and($plan)->toContain('USING INDEX');
})->with([
    'active'          => [null, 'active'],
    'expired'         => [null, 'expired'],
    'all'             => [null, 'all'],
    'filtered active' => ['manual', 'active'],
]);
