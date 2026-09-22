<?php

declare(strict_types=1);

namespace Watchtower\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;
use Symfony\Component\HttpFoundation\Response;
use Watchtower\Services\BlacklistCache;
use Watchtower\Support\BlockResponse;
use Watchtower\Support\FailureWindow;
use Watchtower\Support\IpRange;

class BlockedIpMiddleware
{
    /**
     * Request attribute carrying the canonical client address.
     *
     * Resolving it means re-deriving the client IP through the trusted-proxy
     * chain (Symfony recomputes getClientIps() on every call, it does not
     * memoise) and an inet_pton/inet_ntop round trip. Middleware further
     * down the stack needs the same value and cannot get a different answer,
     * so it is computed once here and read from there.
     */
    public const CLIENT_IP = 'watchtower.ip';

    /**
     * Request attribute carrying this middleware's blocklist verdict.
     *
     * The lookup is two cache reads, and the detectors ask the same question
     * moments later in the same request — AutoBlockService::detect() would
     * otherwise repeat both. The second answer can only differ if a block
     * landed mid-request, which is far too rare to be worth paying for on
     * every matching signal.
     *
     * Absent means this middleware never reached an answer: Watchtower is
     * off, the request has no resolvable address, never_block covered it, or
     * the cache read threw and it failed open. Readers look it up themselves
     * in that case, so the saving never costs correctness.
     */
    public const BLOCKED = 'watchtower.blocked';

    public function __construct(private readonly BlacklistCache $cache) {}

    /**
     * The canonical client address, from handle() when it ran ahead of the
     * caller — which in the assembled stack it always does — and re-derived
     * when it didn't.
     *
     * Reading the attribute keeps every middleware looking at the same
     * address, and is much cheaper than asking again: Symfony recomputes
     * getClientIps() on every call rather than memoising it, so a second
     * call re-walks the trusted-proxy chain and re-parses X-Forwarded-For,
     * then pays another inet_pton/inet_ntop round trip to canonicalise the
     * same string into the same answer.
     *
     * The fallback covers a middleware used on its own, as the unit tests do,
     * and a route group that somehow runs without the global stack — so a
     * scoped block still enforces rather than failing open.
     */
    public static function clientIp(Request $request): ?string
    {
        $stashed = $request->attributes->get(self::CLIENT_IP);

        if (is_string($stashed) && $stashed !== '') {
            return $stashed;
        }

        $ip = $request->ip();

        return $ip === null ? null : (IpRange::canonical($ip) ?? $ip);
    }

    /**
     * The blocklist verdict handle() already paid for, or null when it has
     * none and the caller has to ask for itself. See BLOCKED.
     */
    public static function verdict(Request $request): ?bool
    {
        $stashed = $request->attributes->get(self::BLOCKED);

        return is_bool($stashed) ? $stashed : null;
    }

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

        $request->attributes->set(self::CLIENT_IP, $normalized);

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

        // Only a verdict actually read from the cache is stashed. The paths
        // above return without one, and a reader that finds nothing asks for
        // itself rather than assuming "not blocked".
        $request->attributes->set(self::BLOCKED, $blocked);

        if ($blocked) {
            return BlockResponse::make($request);
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
