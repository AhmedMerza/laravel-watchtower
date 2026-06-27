<?php

declare(strict_types=1);

namespace Watchtower\Http\Controllers;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Routing\Controller;
use Watchtower\Models\BlacklistedIp;
use Watchtower\Services\BlacklistService;

class BlockController extends Controller
{
    public function __construct(private readonly BlacklistService $service) {}

    public function block(Request $request): JsonResponse
    {
        $validated = $request->validate([
            'ip'           => ['required', 'string', 'ip', 'max:50'],
            'reason'       => ['nullable', 'string', 'max:500'],
            'expires_at'   => ['nullable', 'date'],
            'log_entry_id' => ['nullable', 'string', 'max:26'],
        ]);

        $user = $request->user();
        $blockedBy = $user
            ? ($user->getAttribute('email') ?? $user->getAttribute('name'))
            : null;

        try {
            $record = $this->service->block($validated['ip'], [
                'reason'       => $validated['reason'] ?? null,
                'expires_at'   => isset($validated['expires_at']) ? now()->parse($validated['expires_at']) : null,
                'log_entry_id' => $validated['log_entry_id'] ?? null,
                'blocked_by'   => $blockedBy,
            ]);
        } catch (\RuntimeException $e) {
            return response()->json(['error' => $e->getMessage()], 422);
        }

        return response()->json(['data' => $record]);
    }

    public function unblock(string $ip): JsonResponse
    {
        $deleted = $this->service->unblock(urldecode($ip));

        return response()->json(['deleted' => $deleted]);
    }

    public function status(string $ip): JsonResponse
    {
        $ip = urldecode($ip);
        $normalized = $this->service->normalizeIp($ip);

        // Use Redis as source of truth — same check the middleware uses
        $blocked = $this->service->isBlocked($normalized);
        $record = BlacklistedIp::where('ip', $normalized)->first();

        return response()->json([
            'blocked' => $blocked,
            'data'    => $record,
        ]);
    }

    public function index(): JsonResponse
    {
        $blocks = BlacklistedIp::active()->orderByDesc('created_at')->get();

        return response()->json(['data' => $blocks]);
    }
}
