<?php

declare(strict_types=1);

namespace Watchtower\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Str;
use Symfony\Component\HttpFoundation\Response;
use Watchtower\Services\AutoBlockService;
use Watchtower\Support\BlockResponse;

/**
 * The two detectors that read the request itself.
 *
 * - `scanner_paths` matches the path on the way in, so a probe for `/.env`
 *   is answered rather than served.
 * - `response_bursts` counts 404s and 429s on the way out, which needs the
 *   response and so runs in terminate(), after it has been sent.
 *
 * One class because they share a request and an address; one stack frame is
 * cheaper than two, and the provider only registers it when at least one of
 * them is enabled — a stock install never has it in the stack at all.
 *
 * Registered directly after BlockedIpMiddleware, so an address that is
 * already blocked is turned away before handle() runs and can't add to a
 * counter. That ordering does NOT cover terminate(): Laravel terminates
 * every global middleware that has the method, whether or not the pipeline
 * short-circuited, so response_bursts still runs for a request that
 * BlockedIpMiddleware turned away — visibly so if block_response.status is
 * set to 404 to disguise a block. What protects it there is
 * AutoBlockService::record()'s own already-blocked check, which is
 * load-bearing rather than redundant with this ordering.
 */
class SignalDetectorMiddleware
{
    public function __construct(private readonly AutoBlockService $autoBlock) {}

    public function handle(Request $request, Closure $next): Response
    {
        $patterns = $this->scannerPatterns();

        // decodedPath() so `/%2Eenv` is caught the same as `/.env`, and
        // ignoreCase because Str::is() — and so $request->is() — is
        // case-sensitive by default, while scanners vary case precisely to
        // slip past naive matching. `/WP-ADMIN/setup-config.php` is the
        // same probe as `/wp-admin/setup-config.php`.
        if ($patterns !== [] && Str::is($patterns, $request->decodedPath(), true)) {
            // Answer the probe ourselves rather than letting it through and
            // blocking only the next one. The default patterns hit nothing
            // real, but the list is configurable, and a pattern that does
            // overlap a live route would otherwise serve it once before the
            // block took effect.
            if ($this->record('scanner_paths', $request)) {
                return BlockResponse::make();
            }
        }

        return $next($request);
    }

    public function terminate(Request $request, Response $response): void
    {
        $settings = (array) config('watchtower.auto_block.detectors.response_bursts', []);

        if (! ($settings['enabled'] ?? false)) {
            return;
        }

        $statuses = array_map(intval(...), (array) ($settings['statuses'] ?? [404, 429]));

        if (in_array($response->getStatusCode(), $statuses, true)) {
            $this->record('response_bursts', $request);
        }
    }

    /**
     * The configured scanner patterns, as ->is() wants them: no leading
     * slash. They read better in config with one, so accept either.
     *
     * @return list<string>
     */
    private function scannerPatterns(): array
    {
        $settings = (array) config('watchtower.auto_block.detectors.scanner_paths', []);

        if (! ($settings['enabled'] ?? false)) {
            return [];
        }

        return array_values(array_map(
            static fn ($pattern): string => ltrim((string) $pattern, '/'),
            (array) ($settings['patterns'] ?? []),
        ));
    }

    /**
     * Count the signal, naming the signed-in user when there is one.
     *
     * `$request->user()` rather than the Auth facade: this runs at both ends
     * of the stack, and on the way in the session hasn't been started yet.
     * The request's own resolver returns null in that case instead of
     * booting a guard mid-detector — which is the right answer anyway, since
     * a scanner probing `/.env` is nobody.
     */
    private function record(string $detector, Request $request): bool
    {
        $ip = $request->ip();

        if ($ip === null) {
            return false;
        }

        $userId = $request->user()?->getAuthIdentifier();

        return $this->autoBlock->record(
            $detector,
            $ip,
            is_int($userId) || is_string($userId) ? $userId : null,
        );
    }
}
