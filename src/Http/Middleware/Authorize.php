<?php

declare(strict_types=1);

namespace Watchtower\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Gate;
use Symfony\Component\HttpFoundation\Response;

/**
 * Guards the standalone management API with the `viewWatchtower` Gate.
 *
 * Failure is always a 403, never a redirect to a login page: every route
 * behind this is a JSON endpoint, and a client that follows a redirect reads
 * the login page's 200 as success.
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
