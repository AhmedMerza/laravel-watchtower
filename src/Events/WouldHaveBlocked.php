<?php

declare(strict_types=1);

namespace Watchtower\Events;

/**
 * A rule or detector matched an address and nothing was blocked — warn mode,
 * the shared-IP guard, or never_auto_block held it back. Fired alongside the
 * `would_have_blocked` log line, with the same fields.
 */
class WouldHaveBlocked
{
    /**
     * @param  array<string, mixed>  $context  what matched (detector and hits,
     *                                         or rule and index) and, in warn
     *                                         mode, what block mode would have done
     */
    public function __construct(
        public readonly string $ip,
        public readonly string $reason,
        public readonly string $notBlockedBecause,
        public readonly string $scope,
        public readonly array $context = [],
    ) {}
}
