<?php

declare(strict_types=1);

namespace Watchtower\Enums;

enum BlockSource: string
{
    case Manual = 'manual';
    case Auto   = 'auto';
    case Sync   = 'sync';
    // Imported from a public blocklist by watchtower:import-feeds (#21).
    // Local to each environment: never synced, never pushed to a target.
    case Feed   = 'feed';
}
