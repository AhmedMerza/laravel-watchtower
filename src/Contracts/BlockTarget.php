<?php

declare(strict_types=1);

namespace Watchtower\Contracts;

use Watchtower\Models\BlacklistedIp;

/**
 * Somewhere else a block can be sent, besides the local DB and cache this
 * node already enforces against: another Laravel environment, Cloudflare,
 * an nginx deny file.
 *
 * Only ever called for a GLOBAL-scope record — the dispatching listener
 * gates on that once, centrally, before any target is asked to do anything
 * (see DispatchBlockToTargets). A scoped block has no meaning to an edge or
 * infrastructure target: there is no route for it to enforce "only these
 * paths" against.
 *
 * Not `Watchtower\Rules\BlockTarget` — that is an unrelated ValidationRule
 * for IP/CIDR input. Same short name, different namespace, never imported
 * together.
 */
interface BlockTarget
{
    /** A record became (or is still) blocked. Must not throw past the caller — see DispatchBlockToTargets. */
    public function apply(BlacklistedIp $record): void;

    /** $ip is no longer blocked. A target with no record of blocking it does nothing. */
    public function remove(string $ip): void;

    /**
     * Repair drift: make this target's state match $activeBlocks exactly,
     * independent of whatever apply()/remove() calls this node has made (or
     * failed to make) since the target was last in sync.
     *
     * @param  iterable<BlacklistedIp>  $activeBlocks
     */
    public function reconcile(iterable $activeBlocks): void;
}
