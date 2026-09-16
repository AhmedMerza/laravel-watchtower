<?php

declare(strict_types=1);

namespace Watchtower\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;
use Watchtower\Support\SyncSignature;

/**
 * Authenticates satellite → master sync requests.
 *
 * These routes carry no session and no CSRF token — the shared HMAC secret
 * is the only thing standing between the open internet and the ability to
 * block any IP across every environment, so a request that fails any check
 * here is rejected outright.
 */
class VerifySyncSignature
{
    public function handle(Request $request, Closure $next): Response
    {
        $secret = (string) config('watchtower.sync.secret', '');

        // Belt and braces: the routes aren't registered without a secret.
        if ($secret === '') {
            return $this->reject('Sync is not configured on this environment.');
        }

        $timestamp = (string) $request->header(SyncSignature::TIMESTAMP_HEADER, '');
        $signature = (string) $request->header(SyncSignature::SIGNATURE_HEADER, '');

        if ($timestamp === '' || $signature === '') {
            return $this->reject('Missing sync signature headers.');
        }

        if (! ctype_digit($timestamp)) {
            return $this->reject('Malformed sync timestamp.');
        }

        $tolerance = (int) config('watchtower.sync.timestamp_tolerance', 300);

        if (abs(now()->timestamp - (int) $timestamp) > $tolerance) {
            return $this->reject('Sync timestamp outside the accepted window.');
        }

        // The path signed is the route's own URI, not $request->path(): an app
        // mounted in a subdirectory would otherwise see a path the satellite
        // never signed.
        $path = '/'.ltrim((string) $request->route()?->uri(), '/');

        $expected = SyncSignature::compute(
            $timestamp,
            $request->method(),
            $path,
            $request->getContent(),
            $secret
        );

        if (! hash_equals($expected, $signature)) {
            return $this->reject('Invalid sync signature.');
        }

        return $next($request);
    }

    private function reject(string $message): Response
    {
        return response()->json(['error' => $message], 401);
    }
}
