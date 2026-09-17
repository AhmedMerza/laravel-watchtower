<?php

declare(strict_types=1);

namespace Watchtower\Http\Controllers;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Routing\Controller;
use Watchtower\Enums\BlockSource;
use Watchtower\Exceptions\NeverBlockException;
use Watchtower\Models\BlacklistedIp;
use Watchtower\Services\BlacklistService;

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

    /** Satellites pull this to rebuild their local cache. */
    public function blocks(): JsonResponse
    {
        return response()->json(['data' => BlacklistedIp::active()->get()]);
    }

    /** A satellite reporting a block it made locally. */
    public function receive(Request $request): JsonResponse
    {
        $validated = $request->validate([
            'ip'         => ['required', 'string', 'ip', 'max:50'],
            'reason'     => ['nullable', 'string', 'max:500'],
            'source_env' => ['nullable', 'string', 'max:50'],
            'expires_at' => ['nullable', 'date'],
            'blocked_by' => ['nullable', 'string', 'max:255'],
        ]);

        $ip = $this->service->normalizeIp($validated['ip']);
        $existing = BlacklistedIp::where('ip', $ip)->first();

        // Same rule watchtower:sync applies in the other direction: an
        // incoming sync record never downgrades a manual or auto block made
        // here. It also makes a master whose own master_url points at itself
        // a no-op rather than a source rewrite.
        if ($existing && $existing->source !== BlockSource::Sync) {
            return response()->json(['data' => $existing, 'applied' => false]);
        }

        try {
            $record = $this->service->block($ip, [
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
