<?php

declare(strict_types=1);

namespace Watchtower\Http\Controllers;

use Illuminate\Contracts\View\View;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Routing\Controller;
use Illuminate\Support\Facades\Route;
use Illuminate\Validation\Rule;
use Watchtower\Enums\BlockSource;
use Watchtower\Exceptions\NeverBlockException;
use Watchtower\Models\BlacklistedIp;
use Watchtower\Rules\BlockTarget;
use Watchtower\Services\BlacklistService;
use Watchtower\Support\BlockScope;

/**
 * The management page: list, block, unblock, without LogScope installed.
 *
 * Server-rendered on purpose. Every mutation is a plain form POST that
 * redirects back, so the page needs no JavaScript at all — the tool you use
 * to unblock yourself should not be the one thing that stops working when an
 * asset fails to load. It is also why the filters live in the query string:
 * they survive a bookmark, a refresh and a redirect after a block.
 *
 * The JSON API in BlockController is unchanged and stays the integration
 * surface; this page shares its services and its validation rule objects, not
 * its endpoints.
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
        $source = $request->query('source');
        $source = is_string($source) && BlockSource::tryFrom($source) !== null ? $source : null;

        $state = $request->query('state');
        $state = is_string($state) && in_array($state, ['active', 'expired', 'all'], true) ? $state : 'active';

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
        $validated = $request->validate([
            'ip'       => ['required', 'string', 'max:50', new BlockTarget(allowBroad: $request->boolean('force'))],
            'force'    => ['sometimes', 'boolean'],
            'reason'   => ['nullable', 'string', 'max:500'],
            'duration' => ['required', 'string', Rule::in(array_keys(self::DURATIONS))],
            'scope'    => ['nullable', 'string', Rule::in(BlockScope::declared())],
        ]);

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
            return back()->withInput()->withErrors(['ip' => $e->getMessage()]);
        }

        // Reports the stored target rather than what was typed: a single IPv6
        // address is stored as the /64 around it, and an operator who blocks
        // one address needs to see that a network was blocked.
        return back()->with('watchtower_status', $record->scope === BlockScope::GLOBAL
            ? "Blocked {$record->ip}."
            : "Blocked {$record->ip} from the {$record->scope} routes.");
    }

    /**
     * Lift one row's block.
     *
     * Takes the row id, not an address: the list is one row per address per
     * scope, and the button under a row has to lift that row. It also keeps a
     * CIDR out of the URL, and keeps an empty scope out of the request body —
     * the `web` group turns `''` into null, and null means every scope to
     * BlacklistService::unblock(), so a global row's button would have lifted
     * the address's scoped blocks too.
     */
    public function unblock(Request $request): RedirectResponse
    {
        $validated = $request->validate([
            'id' => ['required', 'string', 'max:26'],
        ]);

        $block = BlacklistedIp::find($validated['id']);

        if ($block === null) {
            return back()->with('watchtower_status', 'That block is already gone.');
        }

        $this->service->unblock($block->ip, $block->scope);

        return back()->with('watchtower_status', "Unblocked {$block->ip}.");
    }
}
