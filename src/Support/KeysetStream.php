<?php

declare(strict_types=1);

namespace Watchtower\Support;

use Carbon\CarbonInterface;
use Illuminate\Database\Query\Builder;

/**
 * Log rows from `$query` between two moments, oldest first, a page at a time.
 *
 * Keyset rather than `offset`, and on `(occurred_at, id)` rather than
 * `occurred_at` alone: log rows share a timestamp constantly — a burst is
 * what `watchtower:simulate` exists to find — and a keyset on a non-unique
 * column either repeats rows or skips them at every page boundary. `id` is a
 * ULID, so it breaks the tie in insertion order and the pair is unique.
 *
 * Not `lazyById()`: ordering by `id` alone can lead the planner to walk the
 * primary key and filter, which on a log table means reading every row to
 * find the few that match. Ordering by `occurred_at` first keeps it on the
 * range the `(…, occurred_at)` indexes serve.
 */
final class KeysetStream
{
    /** Rows per page. */
    public const CHUNK = 1000;

    /**
     * @param  list<string>  $columns  read alongside `id` and `occurred_at`
     * @return \Generator<int, \stdClass>
     */
    public static function rows(Builder $query, CarbonInterface $from, CarbonInterface $to, array $columns = []): \Generator
    {
        $lastAt = null;
        $lastId = null;

        while (true) {
            $page = (clone $query)
                ->where('occurred_at', '>=', $from)
                ->where('occurred_at', '<=', $to)
                ->orderBy('occurred_at')
                ->orderBy('id')
                ->limit(self::CHUNK);

            if ($lastAt !== null) {
                $page->where(function (Builder $q) use ($lastAt, $lastId): void {
                    $q->where('occurred_at', '>', $lastAt)
                        ->orWhere(fn (Builder $tie): Builder => $tie
                            ->where('occurred_at', '=', $lastAt)
                            ->where('id', '>', $lastId));
                });
            }

            $rows = $page->get(['id', 'occurred_at', ...$columns]);

            if ($rows->isEmpty()) {
                return;
            }

            yield from $rows;

            $last = $rows->last();
            $lastAt = $last->occurred_at;
            $lastId = $last->id;

            if ($rows->count() < self::CHUNK) {
                return;
            }
        }
    }
}
