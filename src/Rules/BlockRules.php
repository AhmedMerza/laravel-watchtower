<?php

declare(strict_types=1);

namespace Watchtower\Rules;

use Illuminate\Validation\Rule;
use Watchtower\Support\BlockScope;

/**
 * The validation every new block goes through, wherever it was asked for.
 *
 * `POST /api/block` and the management page's block form accept the same
 * target, reason and scope, and differ only in how they express an expiry —
 * the API takes an `expires_at`, the form a duration it can't put in the
 * past. Holding the common part here means a change to any of it is one
 * edit: two copies of a rule is how the divergence in issue #38 started.
 */
final class BlockRules
{
    /**
     * @param  bool  $allowBroad  whether the caller asked to block a range
     *                            wider than IpRange's minimum prefixes
     * @return array<string, array<int, mixed>>
     */
    public static function shared(bool $allowBroad): array
    {
        return [
            'ip'     => ['required', 'string', 'max:50', new BlockTarget(allowBroad: $allowBroad)],
            'force'  => ['sometimes', 'boolean'],
            'reason' => ['nullable', 'string', 'max:500'],
            // Rule::in rather than a free string, so a scope no route carries
            // is refused where the caller can read it instead of becoming a
            // block that enforces nothing. BlacklistService refuses it too;
            // this just says so in the shape the caller's other errors take.
            'scope'  => ['nullable', 'string', Rule::in(BlockScope::declared())],
        ];
    }
}
