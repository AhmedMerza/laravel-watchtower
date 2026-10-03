<?php

declare(strict_types=1);

namespace Watchtower\Events;

/**
 * The global block on $ip is gone.
 *
 * Fired by BlacklistService::remove() only when BlockScope::GLOBAL is among
 * the scopes it removed — never for a scope-only unblock, which must not
 * touch a target that has no notion of scope. $ip is a plain string, not the
 * deleted BlacklistedIp row: by the time this fires the row is gone, and a
 * target only ever needs the address to undo whatever it did for it.
 */
class IpUnblocked
{
    public function __construct(public readonly string $ip) {}
}
