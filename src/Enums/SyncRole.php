<?php

declare(strict_types=1);

namespace Watchtower\Enums;

/**
 * Which end of sync this environment is (#36).
 *
 * The shared secret can't tell: every environment holds it, and
 * WATCHTOWER_MASTER_URL is set identically everywhere, including on the
 * master, where it points at itself. So without a role every environment
 * serves the sync routes and pushes its blocks to the master.
 */
enum SyncRole: string
{
    // Serves the sync routes. Never pushes to, or pulls from, itself.
    case Master    = 'master';
    // Pushes and pulls. Serves nothing.
    case Satellite = 'satellite';

    /**
     * null when unset: the pre-#36 behaviour, where an environment both
     * serves and pushes. An unrecognised value reads as Satellite, so a typo
     * exposes less rather than more. watchtower:sync reports the bad value,
     * and a master with a typo shows up as a 404 on its satellites.
     */
    public static function current(): ?self
    {
        $raw = self::raw();

        return $raw === '' ? null : (self::tryFrom($raw) ?? self::Satellite);
    }

    /** The configured value when it isn't one of the cases, else null. */
    public static function invalid(): ?string
    {
        $raw = self::raw();

        return $raw === '' || self::tryFrom($raw) !== null ? null : $raw;
    }

    /**
     * What to check when the master answers a sync request with $status. A
     * 404 means the master isn't serving the sync routes at all, which a bare
     * status code makes look like a wrong URL or a bad secret.
     */
    public static function hintFor(int $status): string
    {
        return $status === 404
            ? ' — the master is not serving the sync routes. On the master, check that WATCHTOWER_SYNC_SECRET is set and WATCHTOWER_SYNC_ROLE is master or unset.'
            : '';
    }

    private static function raw(): string
    {
        return strtolower(trim((string) config('watchtower.sync.role', '')));
    }
}
