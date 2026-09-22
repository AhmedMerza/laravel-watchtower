<?php

declare(strict_types=1);

namespace Watchtower\Support;

use Illuminate\Http\Request;
use Watchtower\Enums\BlockSource;

/**
 * The list filters, normalised, for both lists that offer them.
 *
 * The management page and `GET /api/blocks` accept the same `source` and
 * `state`, so the whitelisting lives here rather than once per controller.
 * BlacklistedIp::scopeFilter() trusts what it is handed — it does a bare
 * `where('source', $source)` — and two copies of the rule deciding what to
 * hand it is how the divergence in issue #38 started.
 *
 * An unrecognised value is ignored rather than refused: a hand-edited query
 * string shouldn't be an error page on the tool you reach for when something
 * is wrong. That holds for the API too, where the alternative is a 422 on a
 * request that has a perfectly good answer.
 */
final class BlockFilters
{
    /** @var list<string> */
    public const STATES = ['active', 'expired', 'all'];

    /**
     * The filters a request is asking for, whether it carried them in the
     * query string (either list) or as hidden fields (a form posting back).
     *
     * @return array{0: string|null, 1: string}
     */
    public static function fromRequest(Request $request): array
    {
        $source = $request->input('source');
        $source = is_string($source) && BlockSource::tryFrom($source) !== null ? $source : null;

        $state = $request->input('state');
        $state = is_string($state) && in_array($state, self::STATES, true) ? $state : 'active';

        return [$source, $state];
    }
}
