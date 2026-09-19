<?php

declare(strict_types=1);

namespace Watchtower\Support;

use Symfony\Component\HttpFoundation\Response;

/**
 * The response a blocked request gets, built from `block_response` config.
 *
 * Shared because two places answer a blocked request and they must not
 * drift: BlockedIpMiddleware, which turns away an address blocked earlier,
 * and the scanner-path detector, which blocks mid-request and has to answer
 * the same way the middleware would have on the next one.
 */
class BlockResponse
{
    public static function make(): Response
    {
        $config = (array) config('watchtower.block_response', []);

        if (! empty($config['redirect'])) {
            return redirect($config['redirect']);
        }

        return response(
            $config['message'] ?? 'Access denied.',
            (int) ($config['status'] ?? 403),
        );
    }
}
