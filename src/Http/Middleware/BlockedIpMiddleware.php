<?php

declare(strict_types=1);

namespace Watchtower\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;
use Symfony\Component\HttpFoundation\Response;
use Watchtower\Services\BlacklistCache;
use Watchtower\Support\FailureWindow;
use Watchtower\Support\IpRange;

class BlockedIpMiddleware
{
    public function __construct(private readonly BlacklistCache $cache) {}

    public function handle(Request $request, Closure $next): Response
    {
        if (! config('watchtower.enabled', true)) {
            return $next($request);
        }

        $ip = $request->ip();

        if ($ip === null) {
            return $next($request);
        }

        $normalized = IpRange::canonical($ip) ?? $ip;

        // Never block whitelisted IPs or ranges — check before the cache to
        // guarantee safety, so they win over any block that covers them.
        if (IpRange::covers((array) config('watchtower.never_block', []), $normalized)) {
            return $next($request);
        }

        try {
            $blocked = $this->cache->isBlocked($normalized);
        } catch (\Throwable $e) {
            // Fail open: a cache outage must not turn every request into a 500.
            $this->reportCacheFailure($e);

            return $next($request);
        }

        if ($blocked) {
            $blockConfig = config('watchtower.block_response');

            if ($blockConfig['redirect']) {
                return redirect($blockConfig['redirect']);
            }

            return response($blockConfig['message'], $blockConfig['status']);
        }

        return $next($request);
    }

    /**
     * Log the failure at most once per window — every request hits this
     * during an outage, and a log line per request fills the disk.
     */
    private function reportCacheFailure(\Throwable $e): void
    {
        if (FailureWindow::isOpen('cache')) {
            return;
        }

        FailureWindow::open('cache');

        try {
            Log::channel(config('watchtower.log_channel', 'stack'))
                ->error('Watchtower: blocklist cache lookup failed, letting requests through unchecked', [
                    'error' => $e->getMessage(),
                ]);
        } catch (\Throwable) {
            // A broken log channel must not undo the fail-open.
        }
    }
}
