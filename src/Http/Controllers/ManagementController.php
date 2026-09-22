<?php

declare(strict_types=1);

namespace Watchtower\Http\Controllers;

use Illuminate\Contracts\View\View;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Routing\Controller;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Validator;
use Illuminate\Validation\Rule;
use Watchtower\Enums\BlockSource;
use Watchtower\Exceptions\NeverBlockException;
use Watchtower\Models\BlacklistedIp;
use Watchtower\Rules\BlockRules;
use Watchtower\Services\BlacklistService;
use Watchtower\Support\BlockFilters;
use Watchtower\Support\BlockScope;

/**
 * The management page: list, block, unblock, without LogScope installed.
 *
 * Server-rendered on purpose. Every mutation is a plain form POST that
 * redirects to the list, so the page needs no JavaScript at all — the tool
 * you use to unblock yourself should not be the one thing that stops working
 * when an asset fails to load. It is also why the filters live in the query
 * string: they survive a bookmark, a refresh and a redirect after a block.
 *
 * The JSON API in BlockController stays the integration surface; this page
 * shares its services, its validation rules and its list filters, not its
 * endpoints.
 */
class ManagementController extends Controller
{
    /**
     * Rows per page. Deliberately not configurable — one more knob to
     * document and test, on a page where the answer is "enough to scan".
     */
    private const PER_PAGE = 25;

    /**
     * The durations the block form offers, in minutes; null is permanent.
     *
     * The form posts the key, not a datetime, so a caller cannot use this
     * page to write an expiry in the past — which would store a block that
     * never blocks anything. `POST /api/block` still takes an arbitrary
     * `expires_at`, since an API caller has a reason to name one.
     */
    private const DURATIONS = [
        '1h'        => 60,
        '24h'       => 1440,
        '7d'        => 10080,
        'permanent' => null,
    ];

    public function __construct(private readonly BlacklistService $service) {}

    public function index(Request $request): View
    {
        [$source, $state] = BlockFilters::fromRequest($request);

        $blocks = BlacklistedIp::filter($source, $state)
            ->orderByDesc('created_at')
            ->paginate(self::PER_PAGE)
            ->withQueryString();

        // Which row, if any, is asking "really unblock?". A round trip rather
        // than a confirm() dialog keeps the page working without JavaScript.
        $confirm = $request->query('confirm');

        // Annotated because larastan resolves view names against the app's
        // view paths, and a package namespace registered at boot isn't one of
        // them — so `watchtower::index` reads as a plain string to it.
        /** @var view-string $template */
        $template = 'watchtower::index';

        return view($template, [
            'blocks'      => $blocks,
            'confirm'     => is_string($confirm) ? $confirm : null,
            'source'      => $source,
            'state'       => $state,
            'sources'     => BlockSource::cases(),
            'scopes'      => BlockScope::declared(),
            'durations'   => array_keys(self::DURATIONS),
            // Only when LogScope is actually mounted. `log_entry_id` is a
            // bare ULID, not a foreign key, so a stored id means nothing
            // about whether there is anywhere to send the operator.
            'logScopeUrl' => Route::has('logscope.index') ? route('logscope.index') : null,
        ]);
    }

    public function block(Request $request): RedirectResponse
    {
        $validator = Validator::make($request->all(), BlockRules::shared($request->boolean('force')) + [
            'duration' => ['required', 'string', Rule::in(array_keys(self::DURATIONS))],
        ]);

        if ($validator->fails()) {
            return $this->backToList($request)->withInput()->withErrors($validator);
        }

        $validated = $validator->validated();
        $minutes = self::DURATIONS[$validated['duration']];

        // data_get() reads an Eloquent user's attributes and a GenericUser's
        // properties alike, as BlockController does for the same reason.
        $user = $request->user();

        try {
            $record = $this->service->block($validated['ip'], [
                'reason'     => $validated['reason'] ?? null,
                'expires_at' => $minutes === null ? null : now()->addMinutes($minutes),
                'blocked_by' => data_get($user, 'email') ?? data_get($user, 'name'),
                'scope'      => $validated['scope'] ?? null,
            ]);
        } catch (NeverBlockException $e) {
            return $this->backToList($request)->withInput()->withErrors(['ip' => $e->getMessage()]);
        }

        // Sent to the unfiltered list rather than back to the filter they
        // were on: a new block is always active and sorts to the top, and a
        // confirmation for a row the current filter hides reads as a failure.
        //
        // Reports the stored target rather than what was typed, because a
        // single IPv6 address is stored as the /64 around it and an operator
        // who blocks one address needs to see that a network was blocked.
        return redirect()->route('watchtower.ui.index')->with(
            'watchtower_status',
            $record->scope === BlockScope::GLOBAL
                ? "Blocked {$record->ip}."
                : "Blocked {$record->ip} from the {$record->scope} routes.",
        );
    }

    /**
     * Lift one row's block.
     *
     * Takes the row id, not an address: the list is one row per address per
     * scope, and the button under a row has to lift that row. It also keeps a
     * CIDR out of the URL, and keeps an empty scope out of the request body —
     * Laravel's ConvertEmptyStringsToNull turns `''` into null before a
     * controller sees it, and null means every scope to
     * BlacklistService::unblock(), so a global row's button would have lifted
     * the address's scoped blocks too. That middleware is global rather than
     * part of the `web` group, so editing watchtower.routes.middleware can't
     * change it in either direction.
     */
    public function unblock(Request $request): RedirectResponse
    {
        $validator = Validator::make($request->all(), [
            'id' => ['required', 'string', 'max:26'],
        ]);

        if ($validator->fails()) {
            return $this->backToList($request, keepPage: true)->withErrors($validator);
        }

        $block = BlacklistedIp::find($validator->validated()['id']);

        if ($block === null) {
            return $this->backToList($request, keepPage: true)
                ->with('watchtower_status', 'That block is already gone.');
        }

        // Read before the delete, so the message names the address either way.
        $ip = $block->ip;

        // unblockRecord() rather than unblock(): the row's scope is used as
        // stored, so a scope since retired from config can still be cleared.
        // Its false means the row went while this request was in flight —
        // a concurrent unblock, or watchtower:cleanup — and reporting that as
        // a success would tell an operator a block was lifted that wasn't.
        $lifted = $this->service->unblockRecord($block);

        return $this->backToList($request, keepPage: true)->with(
            'watchtower_status',
            $lifted ? "Unblocked {$ip}." : 'That block is already gone.',
        );
    }

    /**
     * A redirect to the list the request came from, keeping its filters.
     *
     * An explicit route, never `back()`: Laravel's `back()` prefers the
     * request's `Referer` header over the session's previous URL and does not
     * require it to point at this app, so every redirect here would otherwise
     * take its destination from a header the sender controls.
     */
    private function backToList(Request $request, bool $keepPage = false): RedirectResponse
    {
        [$source, $state] = BlockFilters::fromRequest($request);

        $parameters = array_filter([
            'source' => $source,
            'state'  => $state === 'active' ? null : $state,
        ]);

        if ($keepPage) {
            $page = (int) $request->input('page', 1);

            if ($page > 1) {
                $parameters['page'] = $page;
            }
        }

        return redirect()->route('watchtower.ui.index', $parameters);
    }
}
