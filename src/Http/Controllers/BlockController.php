<?php

declare(strict_types=1);

namespace Watchtower\Http\Controllers;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Routing\Controller;
use Illuminate\Validation\Rule;
use Watchtower\Exceptions\NeverBlockException;
use Watchtower\Models\BlacklistedIp;
use Watchtower\Rules\BlockRules;
use Watchtower\Services\BlacklistService;
use Watchtower\Support\BlockFilters;
use Watchtower\Support\BlockScope;

class BlockController extends Controller
{
    /**
     * Rows per page when the caller doesn't ask.
     *
     * The same 25 the management page uses, copied rather than shared: the
     * page's number answers "enough to scan on a screen", this one answers
     * "a sensible first page for a client", and there is no reason one
     * moving should drag the other. Nothing enforces that they match.
     */
    private const PER_PAGE = 25;

    /** The most a caller can ask for in one page. */
    private const MAX_PER_PAGE = 100;

    public function __construct(private readonly BlacklistService $service) {}

    public function block(Request $request): JsonResponse
    {
        $validated = $request->validate(BlockRules::shared($request->boolean('force')) + [
            // The API's own two: a caller naming an exact expiry has a reason
            // to, and only a block made from a log entry carries its id.
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

    /**
     * The block list, paginated and filtered.
     *
     * Takes the same `source` and `state` the management page does, through
     * the same normalisation, so the two lists cannot answer the same
     * question differently.
     *
     * This used to return every active block in one array. That is fine for
     * the LogScope panel, which asks about one address, and not something a
     * client can page through — so `data` is now one page of rows, with
     * Laravel's own pagination metadata beside it.
     */
    public function index(Request $request): JsonResponse
    {
        [$source, $state] = BlockFilters::fromRequest($request);

        $blocks = BlacklistedIp::filter($source, $state)
            ->latestFirst()
            ->paginate($this->perPage($request))
            ->withQueryString();

        return response()->json($blocks);
    }

    /**
     * Rows per page: the caller's, within a ceiling.
     *
     * The ceiling is half the point of paginating at all — without it
     * `?per_page=1000000` is the unbounded query this endpoint used to be,
     * spelled differently. A missing or unreadable value takes the default
     * rather than erroring, for the reason BlockFilters gives.
     */
    private function perPage(Request $request): int
    {
        $perPage = $request->input('per_page');

        // is_numeric() before the cast, not $request->integer(): that casts
        // through (int), and (int) on a non-empty array is 1 — so `per_page[]=5`
        // would quietly mean one row per page rather than the default this
        // docblock promises.
        return is_numeric($perPage) && (int) $perPage >= 1
            ? min((int) $perPage, self::MAX_PER_PAGE)
            : self::PER_PAGE;
    }
}
