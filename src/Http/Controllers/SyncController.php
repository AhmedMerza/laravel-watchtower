<?php

declare(strict_types=1);

namespace Watchtower\Http\Controllers;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Routing\Controller;
use Watchtower\Enums\BlockSource;
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

        $ip = $this->service->normalizeTarget($validated['ip']);

        // Scoped to the global row, because that is the only row this can
        // ever write: the payload has no scope field, so block() below
        // stores a global block. Matching any row would let an unrelated
        // LOCAL scoped block for the same address — which is never a Sync
        // block — trip the never-downgrade guard below and silently refuse a
        // satellite's legitimate app-wide block. The pull path in
        // SyncCommand scopes the same lookup for the same reason.
        $existing = BlacklistedIp::where('ip', $ip)
            ->where('scope', BlockScope::GLOBAL)
            ->first();

        // Same rule watchtower:sync applies in the other direction: an
        // incoming sync record never downgrades a manual or auto block made
        // here. It also makes a master whose own master_url points at itself
        // a no-op rather than a source rewrite.
        if ($existing && $existing->source !== BlockSource::Sync) {
            return response()->json(['data' => $existing, 'applied' => false]);
        }

        try {
            $record = $this->service->block($validated['ip'], [
                'reason'     => $validated['reason'] ?? null,
                'source_env' => $validated['source_env'] ?? 'unknown',
                'source'     => BlockSource::Sync,
                'expires_at' => isset($validated['expires_at']) ? now()->parse($validated['expires_at']) : null,
                'blocked_by' => $validated['blocked_by'] ?? null,
            ]);
        } catch (NeverBlockException $e) {
            // never_block on the master wins over a satellite's opinion.
            return response()->json(['error' => $e->getMessage()], 422);
        }

        return response()->json(['data' => $record, 'applied' => true]);
    }
}
