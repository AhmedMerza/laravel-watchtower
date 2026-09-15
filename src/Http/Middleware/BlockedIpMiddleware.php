<?php

declare(strict_types=1);

namespace Watchtower\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;
use Symfony\Component\HttpFoundation\Response;
use Watchtower\Services\BlacklistCache;

class BlockedIpMiddleware
{
    private const FAILURE_LOG_INTERVAL = 60;

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

        $normalized = $this->normalizeIp($ip);

        // Never block whitelisted IPs — check before Redis to guarantee safety
        if (in_array($normalized, config('watchtower.never_block', []), true)) {
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
     * Log the failure at most once per window. A static wouldn't hold the
     * window under PHP-FPM, where statics reset every request, so the marker
     * file's mtime carries it across workers instead.
     */
    private function reportCacheFailure(\Throwable $e): void
    {
        $marker = storage_path('framework/watchtower-cache-failure');

        clearstatcache(true, $marker);
        $lastLoggedAt = @filemtime($marker);

        if ($lastLoggedAt !== false && time() - $lastLoggedAt < self::FAILURE_LOG_INTERVAL) {
            return;
        }

        @touch($marker);

        try {
            Log::channel(config('watchtower.log_channel', 'stack'))
                ->error('Watchtower: blocklist cache lookup failed, letting requests through unchecked', [
                    'error' => $e->getMessage(),
                ]);
        } catch (\Throwable) {
            // A broken log channel must not undo the fail-open.
        }
    }

    private function normalizeIp(string $ip): string
    {
        $packed = @inet_pton($ip);

        if ($packed === false) {
            return $ip;
        }

        $normalized = inet_ntop($packed);

        if (str_starts_with($normalized, '::ffff:')) {
            $candidate = substr($normalized, 7);
            if (filter_var($candidate, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
                return $candidate;
            }
        }

        return $normalized;
    }
}
