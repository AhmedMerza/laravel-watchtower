<?php

declare(strict_types=1);

namespace Watchtower\Tests\Support;

use Illuminate\Filesystem\Filesystem;

use function Orchestra\Testbench\default_skeleton_path;

/**
 * Gives each `--parallel` worker its own copy of testbench's skeleton app.
 *
 * Every worker otherwise boots the same vendor skeleton, so a file one test
 * writes there — a published config or migration, a FailureWindow marker in
 * storage/ — is seen, or deleted, by another worker mid-boot (#160).
 */
final class WorkerSkeleton
{
    private static ?string $path = null;

    /**
     * The worker's skeleton, or null on a serial run (no TEST_TOKEN), which
     * keeps the shared one.
     */
    public static function path(): ?string
    {
        $token = getenv('TEST_TOKEN');

        if ($token === false || $token === '') {
            return null;
        }

        // Copied fresh once per worker process: a run killed mid-test leaves
        // published files in the old copy, and they must not leak forward.
        if (self::$path === null) {
            $path = sys_get_temp_dir().'/watchtower-testbench-'.$token;
            $files = new Filesystem;
            $files->deleteDirectory($path);
            $files->copyDirectory(default_skeleton_path(), $path);
            self::$path = $path;
        }

        return self::$path;
    }
}
