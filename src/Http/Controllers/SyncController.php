<?php

declare(strict_types=1);

namespace Watchtower\Http\Controllers;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Routing\Controller;
use Watchtower\Exceptions\NeverBlockException;
use Watchtower\Models\BlacklistedIp;
use Watchtower\Rules\BlockTarget;
use Watchtower\Services\BlacklistService;
use Watchtower\Support\BlockScope;

/**
 * The master side of cross-environment sync.
 *
 * Kept apart from BlockController: that one serves the human-facing
 * management API behind session auth, this one serves machines behind an
 * HMAC signature. Sharing routes between the two is what produced the
 * CSRF-419 clash these paths replace.
 */
class SyncController extends Controller
{
    public function __construct(private readonly BlacklistService $service) {}

    /**
     * Satellites pull this to rebuild their local cache.
     *
     * Global blocks only. A scoped block means "this address loses the routes
     * carrying watchtower:{scope}", and the satellite has its own route file
     * — it may carry that scope somewhere else entirely, or not at all. The
     * payload has no scope field either, so a scoped row sent here would
     * arrive as a global block and take the address off the whole satellite.
     * `scope` joins the wire format in #37.
     */
    public function blocks(): JsonResponse
    {
        return response()->json([
            'data' => BlacklistedIp::active()->where('scope', BlockScope::GLOBAL)->get(),
        ]);
    }

    /** A satellite reporting a block it made locally. */
    public function receive(Request $request): JsonResponse
    {
        $validated = $request->validate([
            // A satellite already applied its own breadth check, with or
            // without force, so refusing here would only split the two.
            'ip'         => ['required', 'string', 'max:50', new BlockTarget(allowBroad: true)],
            'reason'     => ['nullable', 'string', 'max:500'],
            'source_env' => ['nullable', 'string', 'max:50'],
            'expires_at' => ['nullable', 'date'],
            'blocked_by' => ['nullable', 'string', 'max:255'],
        ]);

        try {
            // The never-downgrade rule, the never_block check and the write
            // are all applySync()'s, which watchtower:sync uses for the pull
            // direction. This path and that one each carried their own copy,
            // and the copies had drifted (#38).
            ['applied' => $applied, 'record' => $record] = $this->service->applySync($validated['ip'], [
                'reason'     => $validated['reason'] ?? null,
                'source_env' => $validated['source_env'] ?? 'unknown',
                'expires_at' => isset($validated['expires_at']) ? now()->parse($validated['expires_at']) : null,
                'blocked_by' => $validated['blocked_by'] ?? null,
            ]);
        } catch (NeverBlockException $e) {
            // never_block on the master wins over a satellite's opinion.
            return response()->json(['error' => $e->getMessage()], 422);
        }

        return response()->json(['data' => $record, 'applied' => $applied]);
    }
}
