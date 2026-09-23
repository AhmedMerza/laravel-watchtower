<?php

declare(strict_types=1);

namespace Watchtower\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;
use Watchtower\Services\AutoBlockService;
use Watchtower\Support\BlockResponse;
use Watchtower\Support\PathMatcher;

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
 * set to 404 to disguise a block. Two things protect it there:
 * AutoBlockService::record()'s own already-blocked check, which is
 * load-bearing rather than redundant with this ordering, and the
 * BlockResponse::ANSWERED marker, which also covers the User-Agent filter's
 * rejections — those do NOT block the address, so the already-blocked check
 * would let them through to the counter.
 */
class SignalDetectorMiddleware
{
    public function __construct(private readonly AutoBlockService $autoBlock) {}

    public function handle(Request $request, Closure $next): Response
    {
        // decodedPath() so `/%2Eenv` is caught the same as `/.env`. Case is
        // folded inside the matcher, because Str::is() — and so
        // $request->is() — is case-sensitive by default, while scanners vary
        // case precisely to slip past naive matching.
        // `/WP-ADMIN/setup-config.php` is the same probe as
        // `/wp-admin/setup-config.php`.
        if (PathMatcher::matchesAny($this->scannerPatterns(), $request->decodedPath())) {
            // Answer the probe ourselves rather than letting it through and
            // blocking only the next one. The default patterns hit nothing
            // real, but the list is configurable, and a pattern that does
            // overlap a live route would otherwise serve it once before the
            // block took effect.
            if ($this->record('scanner_paths', $request)) {
                return BlockResponse::make($request);
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

        // Never count a response Watchtower wrote itself. The already-blocked
        // check covers the address BlockedIpMiddleware turned away, but a
        // User-Agent rejection does not block the address, so without this a
        // `block_response.status` of 404 would feed every rejection straight
        // into the burst counter and block on a threshold it was never
        // tuned for.
        if (BlockResponse::answered($request)) {
            return;
        }

        $statuses = array_map(intval(...), (array) ($settings['statuses'] ?? [404, 429]));

        if (in_array($response->getStatusCode(), $statuses, true)) {
            $this->record('response_bursts', $request);
        }
    }

    /**
     * The configured scanner patterns, exactly as they sit in config.
     *
     * Handed over raw rather than normalised here: PathMatcher strips the
     * leading slash while it compiles, and keys its memo on this array, so
     * rebuilding a normalised copy per request would both duplicate that work
     * and hand the memo a fresh array to miss on every time.
     *
     * @return array<mixed>
     */
    private function scannerPatterns(): array
    {
        $settings = (array) config('watchtower.auto_block.detectors.scanner_paths', []);

        if (! ($settings['enabled'] ?? false)) {
            return [];
        }

        return (array) ($settings['patterns'] ?? []);
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
        $ip = BlockedIpMiddleware::clientIp($request);

        if ($ip === null) {
            return false;
        }

        $userId = $request->user()?->getAuthIdentifier();

        return $this->autoBlock->record(
            $detector,
            $ip,
            is_int($userId) || is_string($userId) ? $userId : null,
            BlockedIpMiddleware::verdict($request),
        );
    }
}
