<?php

declare(strict_types=1);

namespace Watchtower\Http\Controllers;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Routing\Controller;
use Illuminate\Validation\Rule;
use Watchtower\Enums\BlockSource;
use Watchtower\Exceptions\NeverAutoBlockException;
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

    /** Rows per page when a satellite asks for pages. */
    public const PAGE_SIZE = 1000;

    /**
     * Satellites pull this to rebuild their local cache.
     *
     * Global blocks only. A scoped block means "this address loses the routes
     * carrying watchtower:{scope}", and the satellite has its own route file
     * — it may carry that scope somewhere else entirely, or not at all. The
     * payload has no scope field either, so a scoped row sent here would
     * arrive as a global block and take the address off the whole satellite.
     *
     * Paged by id when the satellite sends `after` (#37): 0 for the first
     * page, which sorts before every ULID, then each response's next_cursor
     * until it is null. An id cursor
     * rather than an offset, so a block expiring mid-pull doesn't shift the
     * pages after it, and a block added mid-pull lands on the last one.
     * Without `after` this is the whole list in one response, as before —
     * a satellite older than paging reads only `data`, and handing it the
     * first page would silently drop the rest of the blocklist.
     *
     * The query string isn't signed: the signature covers the route URI, and
     * changing that would break every deployed satellite. A replayed pull
     * with an edited cursor gets a subset of what the signature already
     * allowed, so there is nothing to gain from it.
     */
    public function blocks(Request $request): JsonResponse
    {
        // Not feed rows: every environment imports the feeds itself, and
        // a satellite pulling the master's copy would store thousands of
        // them as `sync` rows that no import ever cleans up (#21).
        //
        // Only the columns SyncCommand reads; the rest is bytes per row per
        // satellite per tick.
        $query = BlacklistedIp::active()
            ->where('scope', BlockScope::GLOBAL)
            ->where('source', '!=', BlockSource::Feed)
            ->select(['id', 'ip', 'reason', 'source_env', 'source', 'expires_at', 'blocked_by']);

        if (! $request->has('after')) {
            return response()->json(['data' => $query->get()->makeHidden('id')]);
        }

        $after = $request->validate(['after' => ['required', 'string', 'max:26']])['after'];

        // One extra row says whether another page exists without a count().
        $rows = $query->where('id', '>', $after)->orderBy('id')->limit(self::PAGE_SIZE + 1)->get();
        $more = $rows->count() > self::PAGE_SIZE;
        $rows = $rows->take(self::PAGE_SIZE);

        return response()->json([
            'data'        => $rows->makeHidden('id')->values(),
            'next_cursor' => $more ? $rows->last()->id : null,
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
            // Optional on purpose: a satellite that predates #56 doesn't send
            // it, and must keep syncing exactly as it does today rather than
            // failing validation the moment this master is upgraded.
            //
            // Manual or Auto only, not the whole enum. PushBlockToMaster
            // returns early on a Sync record, so no honest sender can produce
            // a third value here, and the wire contract should say what it
            // actually accepts. Rule::in over the backed values rather than
            // Rule::enum()->only(), which is newer than the oldest Laravel
            // this package supports.
            'source'     => ['nullable', 'string', Rule::in([
                BlockSource::Manual->value,
                BlockSource::Auto->value,
            ])],
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
                'origin_source' => $validated['source'] ?? null,
            ]);
        } catch (NeverAutoBlockException $e) {
            // Caught before its parent so the satellite is told WHICH list
            // refused it: never_auto_block leaves the door open to an admin
            // here, and never_block does not. Same status either way.
            return response()->json(['error' => $e->getMessage()], 422);
        } catch (NeverBlockException $e) {
            // never_block on the master wins over a satellite's opinion.
            return response()->json(['error' => $e->getMessage()], 422);
        }

        return response()->json(['data' => $record, 'applied' => $applied]);
    }
}
