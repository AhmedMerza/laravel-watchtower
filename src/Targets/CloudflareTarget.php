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

        if ($existing['notes'] === CloudflareApi::NOTE && $existing['mode'] === 'block') {
            // Already applied — this is what makes a retried apply() or a
            // reconcile() replay idempotent.
            return;
        }

        // Cloudflare allows at most one rule per target+value regardless of
        // mode or notes, so attempting create() here would just fail as a
        // duplicate. Raising our own message is clearer than letting that
        // surface — and this case matters: a rule for this value exists but
        // Watchtower didn't create it, which must not look like success.
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
                Log::channel(config('watchtower.log_channel', 'stack'))->warning(
                    'Watchtower: [cloudflare] could not reconcile one record',
                    ['ip' => $record->ip, 'error' => $e->getMessage()]
                );
            }
        }

        foreach ($active as $value => $target) {
            if (! array_key_exists($value, $managed)) {
                $this->api->create($target, $value);
            }
        }

        foreach ($managed as $value => $ruleId) {
            if (! array_key_exists($value, $active)) {
                $this->api->delete($ruleId);
            }
        }
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
