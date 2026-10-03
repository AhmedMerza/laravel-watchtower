<?php

declare(strict_types=1);

namespace Watchtower\Events;

/**
 * The global block on $ip is gone.
 *
 * Fired from two places, both only for a GLOBAL-scope row — never for a
 * scope-only unblock, which must not touch a target that has no notion of
 * scope: BlacklistService::remove() (an explicit unblock, when GLOBAL is
 * among the scopes it removed) and CleanupCommand's expiry sweep (a
 * temporary block lapsing on its own). $ip is a plain string, not the
 * deleted BlacklistedIp row: by the time this fires the row is gone, and a
 * target only ever needs the address to undo whatever it did for it.
 */
class IpUnblocked
{
    public function __construct(public readonly string $ip) {}
}
