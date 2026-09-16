<?php

declare(strict_types=1);

namespace Watchtower\Support;

/**
 * A short "this just failed, don't retry or log it again yet" window,
 * shared across processes.
 *
 * The window lives in a marker file's mtime. It can't live in a static —
 * those reset every request under PHP-FPM, so an outage would still log
 * once per request — and it can't live in the cache, because the failures
 * it throttles are the cache being down.
 */
class FailureWindow
{
    private const SECONDS = 60;

    /**
     * Per-process fallback for when `storage/` isn't writable (read-only
     * containers). It can't span requests under PHP-FPM, but it still
     * throttles a long-running worker, which beats no throttle at all.
     *
     * @var array<string, int>
     */
    private static array $fallback = [];

    public static function isOpen(string $name): bool
    {
        $path = self::path($name);

        clearstatcache(true, $path);
        $openedAt = @filemtime($path);
        $fallbackAt = self::$fallback[$name] ?? false;

        // Take whichever is newer. The marker can exist but be un-touchable —
        // typically created by `php artisan` as the deploy user, then updated
        // by the web user — in which case open() could only record the window
        // in memory and the stale mtime on disk must not shadow it.
        if ($fallbackAt !== false && ($openedAt === false || $fallbackAt > $openedAt)) {
            $openedAt = $fallbackAt;
        }

        return $openedAt !== false && time() - $openedAt < self::SECONDS;
    }

    public static function open(string $name): void
    {
        if (@touch(self::path($name)) === false) {
            self::$fallback[$name] = time();
        }
    }

    /**
     * Clear a window so the next failure logs immediately. Test-only —
     * markers live on disk, so they'd otherwise leak between tests.
     *
     * @internal
     */
    public static function forget(string $name): void
    {
        @unlink(self::path($name));
        unset(self::$fallback[$name]);
    }

    private static function path(string $name): string
    {
        return storage_path('framework/watchtower-'.$name.'-failure');
    }
}
