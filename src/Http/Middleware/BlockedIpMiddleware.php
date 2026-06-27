<?php

declare(strict_types=1);

namespace Watchtower\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;
use Watchtower\Services\BlacklistCache;

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

        $normalized = $this->normalizeIp($ip);

        // Never block whitelisted IPs — check before Redis to guarantee safety
        if (in_array($normalized, config('watchtower.never_block', []), true)) {
            return $next($request);
        }

        if ($this->cache->isBlocked($normalized)) {
            $blockConfig = config('watchtower.block_response');

            if ($blockConfig['redirect']) {
                return redirect($blockConfig['redirect']);
            }

            return response($blockConfig['message'], $blockConfig['status']);
        }

        return $next($request);
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
