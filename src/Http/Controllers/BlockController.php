<?php

declare(strict_types=1);

namespace Watchtower\Http\Controllers;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Routing\Controller;
use Illuminate\Validation\Rule;
use Watchtower\Exceptions\NeverBlockException;
use Watchtower\Models\BlacklistedIp;
use Watchtower\Rules\BlockTarget;
use Watchtower\Services\BlacklistService;
use Watchtower\Support\BlockScope;

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
            // Rule::in rather than a free string, so a scope no route carries
            // is a 422 the caller can read instead of a block that enforces
            // nothing. BlacklistService refuses it too; this just says so in
            // the shape the rest of the endpoint's errors take.
            'scope'        => ['nullable', 'string', Rule::in(BlockScope::declared())],
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
                'scope'        => $validated['scope'] ?? null,
            ]);
        } catch (NeverBlockException $e) {
            return response()->json(['error' => $e->getMessage()], 422);
        }

        return response()->json(['data' => $record]);
    }

    /**
     * Lift a block. With no `scope`, every scope — which is what "unblock
     * this address" has always meant here, and what LogScope's Unblock
     * button says it does. `?scope=auth` lifts just that one.
     */
    public function unblock(Request $request, string $ip): JsonResponse
    {
        $validated = $request->validate([
            'scope' => ['nullable', 'string', Rule::in(BlockScope::declared())],
        ]);

        $deleted = $this->service->unblock(urldecode($ip), $validated['scope'] ?? null);

        return response()->json(['deleted' => $deleted]);
    }

    public function status(string $ip): JsonResponse
    {
        $ip = urldecode($ip);
        $status = $this->service->status($ip);

        return response()->json([
            // `blocked` means blocked app-wide, the question the global
            // middleware answers. A scoped block must not turn it true: a
            // caller acting on it would be acting on an address that can
            // still reach everything but a handful of routes.
            'blocked' => $status['blocked'],
            'data'    => $status['record'],
            'scopes'  => $status['scopes'],
        ]);
    }

    public function index(): JsonResponse
    {
        $blocks = BlacklistedIp::active()->orderByDesc('created_at')->get();

        return response()->json(['data' => $blocks]);
    }
}
