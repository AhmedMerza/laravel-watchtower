<?php

declare(strict_types=1);

namespace Watchtower\Support;

use Watchtower\Contracts\BlockTarget;
use Watchtower\Targets\CloudflareTarget;
use Watchtower\Targets\LaravelTarget;

/**
 * Every BlockTarget this node should apply/remove/reconcile against right
 * now. Resolved through the container rather than `new`d directly so tests
 * can bind a fake target.
 */
final class BlockTargetRegistry
{
    /**
     * @return array<string, BlockTarget> keyed by target name, so a caller
     *                                    can say which one failed
     */
    public function enabled(): array
    {
        $targets = [];

        // `laravel` has no config flag of its own — gated on sync.master_url
        // being set, the same condition LaravelTarget::apply() itself checks
        // (that check stays there too: reconcile() calls apply() per record
        // directly, and a second toggle controlling the same thing would
        // only be confusing). Gating it here as well, rather than always
        // including it, is what makes "no block targets enabled" a real,
        // reportable state for a vanilla single-environment install — and
        // what keeps `watchtower:reconcile` from claiming it "reconciled"
        // a target that was always going to no-op.
        if (config('watchtower.sync.master_url')) {
            $targets['laravel'] = app(LaravelTarget::class);
        }

        // Unlike `laravel`, `cloudflare` has its own enabled flag — nothing
        // else implies it — plus both credentials it needs to call the API
        // at all. Missing either one just leaves the target absent, not a
        // boot-time error.
        if (config('watchtower.block_targets.cloudflare.enabled')
            && config('watchtower.block_targets.cloudflare.account_id')
            && config('watchtower.block_targets.cloudflare.api_token')) {
            $targets['cloudflare'] = app(CloudflareTarget::class);
        }

        // `nginx_file` joins here, gated on its own
        // watchtower.block_targets.nginx_file.enabled, once it exists.

        return $targets;
    }
}
