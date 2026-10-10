<?php

declare(strict_types=1);

namespace Watchtower\Enums;

/**
 * Which blocks a list shows, by expiry. The one place the `state` filter's
 * vocabulary lives: validation (BlockFilters), what each value does
 * (BlacklistedIp::scopeFilter(), whose match has no default arm so a new
 * case can't silently fall through to active) and the management page's
 * <select> all read it (#81).
 */
enum BlockState: string
{
    case Active  = 'active';
    case Expired = 'expired';
    case All     = 'all';

    public function label(): string
    {
        return match ($this) {
            self::Active  => 'Active',
            self::Expired => 'Expired',
            self::All     => 'All',
        };
    }
}
