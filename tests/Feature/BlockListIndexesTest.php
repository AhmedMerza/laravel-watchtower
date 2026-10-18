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
 * This guards the sort only, and only for the views no other index competes
 * for. The expired view and the source filter have their own index —
 * expires_at, (source, created_at) — and seeking it then sorting the few
 * matches is the right plan when matches are rare. On an empty table, with
 * no statistics, which one SQLite picks depends on its version (it differed
 * between local and CI), so their plans are not asserted here.
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
    'active' => [null, 'active'],
    'all'    => [null, 'all'],
]);
