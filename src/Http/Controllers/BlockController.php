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

class BlockController extends Controller
{
    public function __construct(private readonly BlacklistService $service) {}

    public function block(Request $request): JsonResponse
    {
        $validated = $request->validate([
            'ip'           => ['required', 'string', 'max:50', new BlockTarget(allowBroad: $request->boolean('force'))],
            'force'        => ['sometimes', 'boolean'],
            'reason'       => ['nullable', 'string', 'max:500'],
            'expires_at'   => ['nullable', 'date'],
            'log_entry_id' => ['nullable', 'string', 'max:26'],
        ]);

        // data_get() reads an Eloquent user's attributes and a GenericUser's
        // properties alike. The `database` auth provider returns the latter,
        // which has no getAttribute().
        $user = $request->user();
        $blockedBy = data_get($user, 'email') ?? data_get($user, 'name');

        try {
            $record = $this->service->block($validated['ip'], [
                'reason'       => $validated['reason'] ?? null,
                'expires_at'   => isset($validated['expires_at']) ? now()->parse($validated['expires_at']) : null,
                'log_entry_id' => $validated['log_entry_id'] ?? null,
                'blocked_by'   => $blockedBy,
            ]);
        } catch (NeverBlockException $e) {
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
        $record = $this->service->find($ip);

        // For an IP, ask the cache — the same check the middleware uses. A
        // range has no single address to ask about, so its row answers.
        $blocked = str_contains($ip, '/')
            ? $record !== null && ! $record->isExpired()
            : $this->service->isBlocked($ip);

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
