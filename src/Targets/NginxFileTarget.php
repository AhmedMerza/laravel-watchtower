<?php

declare(strict_types=1);

namespace Watchtower\Targets;

use Watchtower\Contracts\BlockTarget;
use Watchtower\Models\BlacklistedIp;
use Watchtower\Support\NginxDenyFile;

/**
 * Pushes a block into an nginx-included deny file, atomically, then runs a
 * configured reload hook.
 *
 * Unlike CloudflareTarget, there's no per-record validation/conflict case to
 * isolate here: nginx's `deny` directive has no CIDR prefix restriction, and
 * the file has no "foreign content" to protect (it's a dedicated include,
 * not a shared namespace an admin might also write to by hand). The one
 * genuinely new risk — a malformed BlacklistedIp::ip being written verbatim
 * into a file nginx then parses and reloads — is handled a layer down, in
 * NginxDenyFile itself, since that's also where the per-record isolation for
 * reconcile() lives (see NginxDenyFile::replaceAll()).
 *
 * No BlockSource::Sync skip, for the same reason as CloudflareTarget: that
 * skip exists only to stop a satellite echoing a pulled-in block back to
 * master, a Laravel-sync-specific loop risk this target has no equivalent
 * of.
 */
class NginxFileTarget implements BlockTarget
{
    public function __construct(private readonly NginxDenyFile $file) {}

    public function apply(BlacklistedIp $record): void
    {
        $this->file->add($record->ip);
    }

    public function remove(string $ip): void
    {
        $this->file->remove($ip);
    }

    /**
     * @param  iterable<BlacklistedIp>  $activeBlocks
     */
    public function reconcile(iterable $activeBlocks): void
    {
        $values = [];

        foreach ($activeBlocks as $record) {
            $values[] = $record->ip;
        }

        $this->file->replaceAll($values);
    }
}
