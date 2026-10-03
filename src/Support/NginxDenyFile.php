<?php

declare(strict_types=1);

namespace Watchtower\Support;

use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Process;

/**
 * Owns the on-disk deny file an nginx `include` points at, and the reload
 * hook that makes nginx pick up a change. NginxFileTarget decides WHAT to
 * do; this class is only HOW to say it on disk — the same split
 * CloudflareTarget/CloudflareApi already use.
 *
 * The whole file is unconditionally ours (unlike Cloudflare's account-wide
 * rule namespace, which an admin can also write into by hand): a header
 * comment plus one sorted `deny {value};` per line. There is nothing here
 * for "foreign content" detection to do.
 *
 * Reads `watchtower.block_targets.nginx_file.{path,reload_command}` at the
 * point of each call, not via the constructor — same reasoning as
 * CloudflareApi reading its config at call time.
 *
 * Not `final`, deliberately — NginxFileTargetTest mocks this class directly,
 * the same way CloudflareTargetTest mocks CloudflareApi.
 */
class NginxDenyFile
{
    public const HEADER = '# Managed by laravel-watchtower — do not edit by hand.';

    private const RELOAD_TIMEOUT_SECONDS = 10;

    /**
     * $value joins the set if it isn't already there. Rejects anything
     * IpRange::canonical() can't make sense of rather than writing it
     * verbatim into a file nginx will parse and reload — unlike Cloudflare,
     * nothing else stands between a malformed BlacklistedIp::ip and this
     * target (AutoBlockService::blockOrReport() calls the blacklist service
     * directly, bypassing the HTTP validation rule entirely).
     */
    public function add(string $value): void
    {
        $canonical = $this->canonicalOrThrow($value);

        $this->withLock(function () use ($canonical) {
            $values = $this->currentValues();

            if (in_array($canonical, $values, true)) {
                return;
            }

            $values[] = $canonical;

            $this->commit($values);
        });
    }

    /** $value leaves the set if it's there. No-op if it never was. */
    public function remove(string $value): void
    {
        $canonical = IpRange::canonical($value);

        if ($canonical === null) {
            // Nothing canonical could ever have been added under this raw
            // value in the first place — never written, so nothing to do.
            return;
        }

        $this->withLock(function () use ($canonical) {
            $values = $this->currentValues();

            $filtered = array_values(array_diff($values, [$canonical]));

            if ($filtered === $values) {
                return;
            }

            $this->commit($filtered);
        });
    }

    /**
     * Makes the file's set exactly $values, in one atomic step — the
     * reconcile() primitive. A value IpRange::canonical() rejects is
     * skipped and logged rather than aborting the whole write: one bad
     * record among many active blocks shouldn't keep the rest out of the
     * enforcement file.
     *
     * @param  array<string>  $values
     */
    public function replaceAll(array $values): void
    {
        $canonical = [];

        foreach ($values as $value) {
            $resolved = IpRange::canonical($value);

            if ($resolved === null) {
                $this->logSkip($value, 'could not canonicalize for the nginx deny file');

                continue;
            }

            $canonical[] = $resolved;
        }

        $this->withLock(function () use ($canonical) {
            $current = $this->currentValues();
            $target = array_values(array_unique($canonical));
            sort($target);

            // is_file(), not just the content comparison: a never-created
            // file and an empty-but-present one both read back as [] from
            // currentValues(), but they're not the same state — nginx needs
            // the file to literally exist before its `include` can load, and
            // "run watchtower:reconcile once" (see docs/block-targets.md) is
            // the documented way to create it on a fresh install that has no
            // active blocks yet. Without this, that first reconcile would
            // silently do nothing.
            if ($target === $current && is_file($this->path())) {
                return;
            }

            $this->commit($target);
        });
    }

    private function canonicalOrThrow(string $value): string
    {
        $canonical = IpRange::canonical($value);

        if ($canonical === null) {
            throw new \RuntimeException("'{$value}' is not a valid IP or CIDR range — refusing to write it into the nginx deny file.");
        }

        return $canonical;
    }

    /**
     * Writes $values (already canonical) if they differ from what's on
     * disk, then reloads — both skipped when nothing actually changed, which
     * is what makes replaceAll() idempotent and keeps watchtower:reconcile
     * from reloading nginx on every tick that found no drift.
     *
     * @param  array<string>  $values
     */
    private function commit(array $values): void
    {
        sort($values);

        $this->writeValues($values);
        $this->reload();
    }

    /** @return array<string> */
    private function currentValues(): array
    {
        $path = $this->path();

        if (! is_file($path)) {
            return [];
        }

        $values = [];

        foreach (file($path, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) ?: [] as $line) {
            if (preg_match('/^\s*deny\s+(.+);\s*$/', $line, $matches) === 1) {
                $values[] = $matches[1];
            }
        }

        return $values;
    }

    /**
     * Temp file in the same directory, then rename() over the real path —
     * atomic on the same filesystem, so a crash mid-write never leaves a
     * half-written file.
     *
     * @param  array<string>  $values
     */
    private function writeValues(array $values): void
    {
        // The directory's existence/writability is already checked by
        // withLock() before this is ever called — same directory, since the
        // lock file sits beside the data file.
        $path = $this->path();
        $dir = dirname($path);

        $lines = array_map(static fn (string $value) => "deny {$value};", $values);
        $content = self::HEADER.\PHP_EOL.implode(\PHP_EOL, $lines).\PHP_EOL;

        $tmp = $dir.'/.'.basename($path).'.'.bin2hex(random_bytes(6)).'.tmp';

        if (file_put_contents($tmp, $content) === false) {
            throw new \RuntimeException("Could not write a temp file in {$dir} for the nginx deny file.");
        }

        if (! rename($tmp, $path)) {
            @unlink($tmp);

            throw new \RuntimeException("Could not move the written temp file into place at {$path}.");
        }
    }

    private function reload(): void
    {
        $command = config('watchtower.block_targets.nginx_file.reload_command');

        if (! $command) {
            // No command configured is valid — e.g. a systemd path unit
            // watching the file handles the reload out of band instead.
            return;
        }

        $result = Process::timeout(self::RELOAD_TIMEOUT_SECONDS)->run($command);

        if ($result->failed()) {
            throw new \RuntimeException(
                "The nginx reload command failed (exit {$result->exitCode()}): {$result->errorOutput()}"
            );
        }
    }

    /**
     * Runs $callback with an exclusive lock held on a dedicated {path}.lock
     * file — never on the data file itself. flock() is tied to an inode;
     * writeValues() replaces the data file's inode via rename(), so a lock
     * held on it would desync the moment that happens. A lock file that's
     * never replaced doesn't have this problem, and flock() self-releases
     * on process death, so a crash mid-operation can't wedge it for the
     * next run.
     */
    private function withLock(callable $callback): void
    {
        $lockPath = $this->path().'.lock';
        $dir = dirname($lockPath);

        if (! is_dir($dir) || ! is_writable($dir)) {
            throw new \RuntimeException(
                "The nginx deny file's directory ({$dir}) doesn't exist or isn't writable by this process — see docs/block-targets.md."
            );
        }

        $handle = fopen($lockPath, 'c+');

        if ($handle === false) {
            throw new \RuntimeException("Could not open the lock file at {$lockPath}.");
        }

        try {
            flock($handle, LOCK_EX);
            $callback();
        } finally {
            flock($handle, LOCK_UN);
            fclose($handle);
        }
    }

    private function path(): string
    {
        return (string) config('watchtower.block_targets.nginx_file.path');
    }

    private function logSkip(string $value, string $reason): void
    {
        Log::channel(config('watchtower.log_channel', 'stack'))->warning(
            'Watchtower: [nginx_file] could not reconcile one record',
            ['ip' => $value, 'error' => $reason]
        );
    }
}
