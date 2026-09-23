<?php

declare(strict_types=1);

namespace Watchtower\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;
use Symfony\Component\HttpFoundation\Response;
use Watchtower\Services\BlacklistCache;
use Watchtower\Support\BlockResponse;
use Watchtower\Support\BlockScope;
use Watchtower\Support\FailureWindow;
use Watchtower\Support\NeverBlockList;

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

        $ip = BlockedIpMiddleware::clientIp($request);

        if ($ip === null) {
            return $next($request);
        }

        // Never block whitelisted IPs or ranges — checked before the cache,
        // and before any scope is consulted, so the guarantee `never_block`
        // makes is the same one on every route.
        if (NeverBlockList::neverBlock($ip)) {
            return $next($request);
        }

        // Resolved once, not once per scope: isDeclared() rebuilds the list
        // from config on every call, and this is the request path.
        $declared = BlockScope::declared();

        foreach ($scopes as $scope) {
            // An undeclared scope can hold no blocks at all — block() refuses
            // them — so there is nothing here to look up. Skipping is not
            // tidiness: its cache namespace is never written, so every lookup
            // would read it as cold and warm it, turning one typo in a route
            // file into a full blocklist rebuild from the DB on every single
            // request to that route.
            if (! in_array($scope, $declared, true)) {
                $this->reportUndeclaredScope($scope);

                continue;
            }

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
     * Say once that a route names a scope the config doesn't declare.
     *
     * Its own window rather than the one AutoBlockService uses for the same
     * mistake in config, so a typo in a route file can't silence a typo in a
     * rule for the next minute — they are fixed in different places.
     */
    private function reportUndeclaredScope(string $scope): void
    {
        if (FailureWindow::isOpen('route_scope')) {
            return;
        }

        FailureWindow::open('route_scope');

        try {
            Log::channel(config('watchtower.log_channel', 'stack'))
                ->warning('Watchtower: a route names a block scope that is not declared, so it enforces nothing', [
                    'scope'    => $scope,
                    'declared' => BlockScope::declared(),
                ]);
        } catch (\Throwable) {
            // A broken log channel must not turn this into a failed request.
        }
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
