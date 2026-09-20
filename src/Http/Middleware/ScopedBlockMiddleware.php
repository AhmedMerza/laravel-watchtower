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

/**
 * Turns away an address blocked in one scope, on the routes that carry it.
 *
 *     Route::middleware('watchtower:auth')->group(function () {
 *         Route::post('/login', [AuthController::class, 'store']);
 *     });
 *
 * This is the middle option between blocking an address everywhere and
 * letting it carry on. A shared address — a carrier NAT, an office, a VPN
 * exit — can lose the login routes while the other people behind it keep
 * using the app with the sessions they already have.
 *
 * A globally blocked address never reaches this: BlockedIpMiddleware runs in
 * the global stack and has already answered. So this only ever asks about one
 * scope's own blocks, and a request to a route without this middleware reads
 * exactly the cache keys it always did.
 */
class ScopedBlockMiddleware
{
    public function __construct(private readonly BlacklistCache $cache) {}

    /**
     * `watchtower:auth` names one scope; `watchtower:auth,admin` names two
     * and blocks an address blocked in either. Each extra scope is another
     * pair of cache reads on that route, so name only the ones it needs.
     */
    public function handle(Request $request, Closure $next, string ...$scopes): Response
    {
        if (! config('watchtower.enabled', true)) {
            return $next($request);
        }

        $ip = $this->clientIp($request);

        if ($ip === null) {
            return $next($request);
        }

        // Never block whitelisted IPs or ranges — checked before the cache,
        // and before any scope is consulted, so the guarantee `never_block`
        // makes is the same one on every route.
        if (IpRange::covers((array) config('watchtower.never_block', []), $ip)) {
            return $next($request);
        }

        foreach ($scopes as $scope) {
            try {
                $blocked = $this->cache->isBlocked($ip, $scope);
            } catch (\Throwable $e) {
                // Fail open, exactly as the global middleware does. These
                // routes are the ones an app can least afford to turn into a
                // 500 — a dead cache backend must not take the login page
                // down with it.
                $this->reportCacheFailure($e, $scope);

                return $next($request);
            }

            if ($blocked) {
                // $request must be passed so the response is marked ANSWERED:
                // terminate() runs on global middleware even when the
                // pipeline short-circuits here, and `response_bursts` would
                // otherwise count our own block response as the app's.
                return BlockResponse::make($request);
            }
        }

        return $next($request);
    }

    /**
     * The canonical client address BlockedIpMiddleware already resolved.
     *
     * Reading its attribute rather than re-deriving keeps the two middleware
     * looking at the same address — Symfony recomputes getClientIps() on every
     * call and a proxy config change mid-request would otherwise let them
     * disagree. The fallback covers a route group that somehow runs without
     * the global middleware, so this still enforces rather than failing open.
     */
    private function clientIp(Request $request): ?string
    {
        $resolved = $request->attributes->get(BlockedIpMiddleware::CLIENT_IP);

        if (is_string($resolved) && $resolved !== '') {
            return $resolved;
        }

        $ip = $request->ip();

        return $ip === null ? null : (IpRange::canonical($ip) ?? $ip);
    }

    /**
     * Log the failure at most once per window — every request to these routes
     * hits this during an outage, and a log line per request fills the disk.
     */
    private function reportCacheFailure(\Throwable $e, string $scope): void
    {
        if (FailureWindow::isOpen('cache')) {
            return;
        }

        FailureWindow::open('cache');

        try {
            Log::channel(config('watchtower.log_channel', 'stack'))
                ->error('Watchtower: scoped blocklist cache lookup failed, letting requests through unchecked', [
                    'scope' => $scope,
                    'error' => $e->getMessage(),
                ]);
        } catch (\Throwable) {
            // A broken log channel must not undo the fail-open.
        }
    }
}
