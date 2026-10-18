<?php

declare(strict_types=1);

namespace Watchtower\Support;

use Illuminate\Support\Facades\Http;
use Watchtower\Enums\SyncRole;
use Watchtower\Exceptions\MasterPullException;

/**
 * Reads the master's active global blocks (feed rows excluded — see
 * SyncController::blocks()), one page per yield. Shared by watchtower:sync,
 * which applies them, and LaravelTarget::reconcile(), which compares them
 * against what this node should have pushed.
 */
final class MasterBlocks
{
    /**
     * @return \Generator<int, list<array<string, mixed>>>
     *
     * @throws MasterPullException
     */
    public static function pages(string $masterUrl, string $secret): \Generator
    {
        // Page until the master says there is no more (#37). A master older
        // than paging ignores `after` and sends no next_cursor, so against
        // one this is a single request for the whole list. The cursor is a
        // ULID; '0' sorts before every one of them.
        $cursor = '0';

        do {
            $response = Http::withHeaders(
                SyncSignature::headers('GET', SyncSignature::PULL_PATH, '', $secret)
                + ['Accept' => 'application/json']
            )->get(rtrim($masterUrl, '/').SyncSignature::PULL_PATH, ['after' => $cursor]);

            if (! $response->successful()) {
                throw new MasterPullException(
                    "master returned HTTP {$response->status()}.".SyncRole::hintFor($response->status()),
                    $response->status(),
                );
            }

            $next = $response->json('next_cursor');

            // A cursor that doesn't move forward would loop forever, and one
            // that only grows longer could too, so it must also be a ULID —
            // the shape the master's ids have. strcmp, not <=: PHP compares
            // numeric-looking strings as numbers.
            if ($next !== null && (! is_string($next) || ! preg_match('/^[0-9a-z]{26}$/i', $next) || strcmp($next, $cursor) <= 0)) {
                throw new MasterPullException("master returned an invalid next_cursor after {$cursor}.");
            }

            yield $response->json('data', []);

            $cursor = $next;
        } while ($cursor !== null);
    }
}
