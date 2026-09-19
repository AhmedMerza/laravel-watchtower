<?php

declare(strict_types=1);

namespace Watchtower\Support;

use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * The response a blocked request gets, built from `block_response` config.
 *
 * Shared because three places answer a blocked request and they must not
 * drift: BlockedIpMiddleware, which turns away an address blocked earlier;
 * the scanner-path detector, which blocks mid-request and has to answer the
 * same way the middleware would have on the next one; and the User-Agent
 * filter, which rejects the request without blocking anything.
 */
class BlockResponse
{
    /**
     * Request attribute marking a request Watchtower itself answered.
     *
     * `response_bursts` reads the status in terminate(), which Laravel runs
     * on every global middleware whether or not the pipeline short-circuited
     * — so without this it would count our own block response as if the app
     * had produced it. That matters as soon as `block_response.status` is
     * set to 404 or 429, which the config suggests as a way to disguise a
     * block: every rejection would feed the burst counter.
     *
     * An address turned away by BlockedIpMiddleware is already blocked, so
     * AutoBlockService::record()'s own already-blocked check absorbs that
     * case. A User-Agent rejection does NOT block the address, so nothing
     * absorbed it before this.
     */
    public const ANSWERED = 'watchtower.answered';

    public static function make(?Request $request = null): Response
    {
        $request?->attributes->set(self::ANSWERED, true);

        $config = (array) config('watchtower.block_response', []);

        if (! empty($config['redirect'])) {
            return redirect($config['redirect']);
        }

        return response(
            $config['message'] ?? 'Access denied.',
            (int) ($config['status'] ?? 403),
        );
    }

    /**
     * Whether Watchtower already answered this request itself.
     */
    public static function answered(Request $request): bool
    {
        return $request->attributes->get(self::ANSWERED) === true;
    }
}
