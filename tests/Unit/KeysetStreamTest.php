<?php

declare(strict_types=1);

use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use Watchtower\Support\KeysetStream;
use Watchtower\Support\SignalLog;

it('streams every row once, in order, across pages that split a run of equal timestamps', function () {
    Carbon::setTestNow('2026-09-21 12:00:00');

    // 2,500 rows: the middle 1,500 share one second, so two page boundaries
    // land inside the tie — the case the keyset's id tiebreak exists for,
    // and the one a page seeking from the last timestamp must not lose.
    $rows = array_map(static fn (int $i): array => [
        'detector'    => 'response_bursts',
        'ip'          => '10.0.0.1',
        'occurred_at' => now()->subHours(2)->addSeconds(match (true) {
            $i < 500  => $i,
            $i < 2000 => 600,
            default   => 600 + $i,
        }),
    ], range(0, 2499));

    foreach (array_chunk($rows, 500) as $chunk) {
        DB::table(SignalLog::TABLE)->insert($chunk);
    }

    $seen = [];

    foreach (KeysetStream::rows(DB::table(SignalLog::TABLE), now()->subHours(3), now()) as $row) {
        $seen[] = [(string) $row->occurred_at, (int) $row->id];
    }

    $sorted = $seen;
    sort($sorted);

    expect($seen)->toHaveCount(2500)
        ->and(array_unique(array_column($seen, 1)))->toHaveCount(2500)
        ->and($seen)->toBe($sorted);

    Carbon::setTestNow();
});
