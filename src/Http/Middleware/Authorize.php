<?php

declare(strict_types=1);

namespace Watchtower\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Gate;
use Symfony\Component\HttpFoundation\Response;

/**
 * Guards the standalone management API and page with the `viewWatchtower`
 * Gate.
 *
 * Failure is always a 403, never a redirect to a login page. The API routes
 * behind this are JSON endpoints, and a client that follows a redirect reads
 * the login page's 200 as success. The management page is served to a
 * browser, where a redirect would be conventional — but it stays a 403 too:
 * an app that wants unauthenticated visitors sent to a login screen has a
 * place to say so already, `watchtower.routes.middleware`, and 'auth' runs
 * before this check.
 */
class Authorize
{
    public function handle(Request $request, Closure $next): Response
    {
        if (! Gate::forUser($request->user())->allows('viewWatchtower')) {
            abort(403, 'Unauthorized access to Watchtower.');
        }

        return $next($request);
    }
}
