<?php

declare(strict_types=1);

namespace Watchtower\Targets;

use Illuminate\Support\Facades\Log;
use Watchtower\Contracts\BlockTarget;
use Watchtower\Models\BlacklistedIp;
use Watchtower\Support\CloudflareApi;
use Watchtower\Support\IpRange;

/**
 * Pushes a block to Cloudflare as an account-level IP Access Rule.
 *
 * Unlike LaravelTarget, a Sync-sourced record is NOT skipped here: that skip
 * exists only to stop a satellite echoing a pulled-in block back to master,
 * a Laravel-sync-specific loop risk Cloudflare has no equivalent of. A
 * Sync-sourced global block is a real block Cloudflare must still enforce —
 * it just never reaches here live (pull-sync fires no IpBlocked event), only
 * through reconcile(), which is the documented reason watchtower:reconcile
 * exists at all for a satellite running this target.
 */
class CloudflareTarget implements BlockTarget
{
    public function __construct(private readonly CloudflareApi $api) {}

    public function apply(BlacklistedIp $record): void
    {
        [$target, $value] = self::resolveTarget($record->ip);

        $existing = $this->api->findRule($target, $value);

        if ($existing === null) {
            $this->api->create($target, $value);

            return;
        }

        if ($existing['notes'] === CloudflareApi::NOTE) {
            if ($existing['mode'] === 'block') {
                // Already applied — this is what makes a retried apply() or
                // a reconcile() replay idempotent.
                return;
            }

            // Watchtower's own rule, drifted out of block mode (e.g. changed
            // by hand in the dashboard). Cloudflare allows at most one rule
            // per target+value regardless of mode, so create() would just
            // fail as a duplicate — raise our own message instead, and keep
            // it distinct from the foreign-rule case below: this rule IS
            // ours, it's just wrong, which is a different fix for whoever
            // reads the log.
            throw new \RuntimeException(
                "Cloudflare has a rule Watchtower created for {$value}, but it's in mode '{$existing['mode']}' instead of 'block' — refusing to overwrite it."
            );
        }

        // A rule for this value exists that Watchtower did not create, which
        // must not look like success.
        throw new \RuntimeException(
            "Cloudflare already has a rule for {$value} (mode: {$existing['mode']}) that Watchtower did not create — refusing to replace it."
        );
    }

    public function remove(string $ip): void
    {
        [$target, $value] = self::resolveTarget($ip);

        $existing = $this->api->findRule($target, $value);

        if ($existing === null || $existing['notes'] !== CloudflareApi::NOTE) {
            // No rule, or one Watchtower didn't create — never delete a rule
            // this target didn't create.
            return;
        }

        $this->api->delete($existing['id']);
    }

    /**
     * @param  iterable<BlacklistedIp>  $activeBlocks
     */
    public function reconcile(iterable $activeBlocks): void
    {
        $managed = $this->api->listManaged();

        $active = [];

        foreach ($activeBlocks as $record) {
            try {
                $active[$record->ip] = self::resolveTarget($record->ip)[0];
            } catch (\RuntimeException $e) {
                // A record Cloudflare's ip_range can't express (see
                // resolveTarget()) — skip just this one so the rest of the
                // set still reconciles, rather than aborting the whole run.
                $this->logSkip($record->ip, $e->getMessage());
            }
        }

        foreach ($active as $value => $target) {
            $existing = $managed[$value] ?? null;

            if ($existing !== null) {
                if ($existing['mode'] === 'block') {
                    continue; // already correctly applied
                }

                // Watchtower's own rule, drifted out of block mode — the
                // same conflict apply() refuses to overwrite (see apply()),
                // just non-fatal here: flag it and move on to the rest of
                // the batch rather than silently treating it as in sync.
                $this->logSkip($value, "its own rule is in mode '{$existing['mode']}' instead of 'block'");

                continue;
            }

            try {
                $this->api->create($target, $value);
            } catch (\Throwable $e) {
                // One item's failure (a foreign rule already occupying this
                // value, a transient Cloudflare error, a rate limit, a real
                // connection failure) must not abort the rest of the batch —
                // that would also skip the delete loop below entirely,
                // undermining reconcile's own purpose for every other record
                // in this run. \Throwable, not \RuntimeException: a network
                // failure from the HTTP client is an Exception, not a
                // RuntimeException, and must be caught here too.
                $this->logSkip($value, $e->getMessage());
            }
        }

        foreach ($managed as $value => $info) {
            if (array_key_exists($value, $active)) {
                continue;
            }

            try {
                $this->api->delete($info['id']);
            } catch (\Throwable $e) {
                $this->logSkip($value, $e->getMessage());
            }
        }
    }

    private function logSkip(string $ip, string $reason): void
    {
        Log::channel(config('watchtower.log_channel', 'stack'))->warning(
            'Watchtower: [cloudflare] could not reconcile one record',
            ['ip' => $ip, 'error' => $reason]
        );
    }

    /**
     * Which Cloudflare configuration target+value a stored block maps to.
     * A bare address is 'ip'; an explicit CIDR is 'ip_range', but Cloudflare
     * only accepts specific prefix lengths there (IPv4 /16 or /24; IPv6 /32,
     * /48, /64) — narrower than what this repo's own validation allows an
     * admin to submit (see Watchtower\Rules\BlockTarget), so a range outside
     * that set is rejected here with a specific message rather than left to
     * surface as an opaque Cloudflare HTTP 400.
     *
     * @return array{string, string}
     */
    private static function resolveTarget(string $value): array
    {
        if (! str_contains($value, '/')) {
            return ['ip', $value];
        }

        [$address, $length] = IpRange::split($value);
        $isIpv6 = str_contains($address, ':');
        $accepted = $isIpv6 ? [32, 48, 64] : [16, 24];

        if (! in_array($length, $accepted, true)) {
            $family = $isIpv6 ? 'IPv6' : 'IPv4';
            $list = implode(', ', array_map(fn ($prefix) => "/{$prefix}", $accepted));

            throw new \RuntimeException(
                "Cloudflare does not support a /{$length} range for {$family} (accepted: {$list}) — cannot push {$value}."
            );
        }

        return ['ip_range', $value];
    }
}
