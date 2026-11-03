<?php

declare(strict_types=1);

namespace Watchtower\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Log;
use Symfony\Component\HttpFoundation\Response;
use Watchtower\Services\AutoBlockService;
use Watchtower\Services\UserAgentFilter;
use Watchtower\Support\BlockResponse;
use Watchtower\Support\NeverBlockList;

/**
 * Turns away requests whose User-Agent names a known attack tool.
 *
 * Registered after BlockedIpMiddleware — an address already blocked is
 * turned away before this runs — and after SignalDetectorMiddleware, so a
 * scanner probing `/.env` is counted toward a real IP block before its
 * User-Agent gets it rejected. This check only decides about one request;
 * the detectors decide about the address, which outlives it, and the
 * stronger signal should get first look at the traffic.
 *
 * The `never_block` check is repeated here rather than inherited from
 * BlockedIpMiddleware: Laravel gives each middleware its own frame, and the
 * guarantee that a whitelisted address is never turned away has to hold in
 * whichever frame does the turning away. It costs a second pass over a list
 * that is typically a handful of entries, and only on installs that have
 * switched this on.
 */
class UserAgentMiddleware
{
    /** One rejection line per address and reason in this many seconds. */
    private const LOG_WINDOW_SECONDS = 60;

    public function __construct(
        private readonly UserAgentFilter $filter,
        private readonly AutoBlockService $autoBlock,
    ) {}

    public function handle(Request $request, Closure $next): Response
    {
        if (! config('watchtower.enabled', true) || ! config('watchtower.user_agents.enabled', true)) {
            return $next($request);
        }

        $agent = $request->userAgent();

        // An absent or blank User-Agent is deliberately not a signal.
        // Webhooks, health checks, uptime monitors and plenty of real API
        // clients send none, and the lists that treat that as hostile are
        // the reason people turn this kind of filtering off again.
        if ($agent === null || trim($agent) === '') {
            return $next($request);
        }

        $normalized = BlockedIpMiddleware::clientIp($request);

        if ($normalized !== null && NeverBlockList::neverBlock($normalized)) {
            return $next($request);
        }

        $reason = $this->filter->reject($agent, $normalized);

        if ($reason === null) {
            return $next($request);
        }

        $this->count($normalized, $request);
        $this->report($reason, $agent, $normalized);

        return BlockResponse::make($request);
    }

    /**
     * Count the rejection against the address, when `bad_user_agent` is
     * armed.
     *
     * Checked here rather than left to AutoBlockService::record() so that a
     * stock install — where the detector is off — does no work at all on a
     * rejection beyond answering it. When it IS armed, record() applies
     * every guard a log rule gets: mode, never_auto_block, and the
     * shared-IP threshold.
     */
    private function count(?string $ip, Request $request): void
    {
        if ($ip === null || ! config('watchtower.auto_block.detectors.bad_user_agent.enabled', false)) {
            return;
        }

        // `$request->user()` rather than the Auth facade, for the reason
        // SignalDetectorMiddleware gives: this runs before the session has
        // started, and the resolver returns null there instead of booting a
        // guard mid-middleware. A token guard can still answer, and a
        // signed-in user behind a scanner User-Agent is exactly the case
        // the shared-IP guard should get to see.
        $userId = $request->user()?->getAuthIdentifier();

        $this->autoBlock->record(
            'bad_user_agent',
            $ip,
            is_int($userId) || is_string($userId) ? $userId : null,
            BlockedIpMiddleware::verdict($request),
            // Not the User-Agent itself: it is whatever the client chose to
            // send, and the filter's debug line already records it.
            ['path' => $request->decodedPath()],
        );
    }

    /**
     * Leave a trace, at debug level, once per address and reason a minute.
     *
     * A filter that silently drops requests is miserable to operate — "why
     * is this client getting a 403" has to be answerable. The line is
     * throttled because a scanner's request rate must not set the log's
     * growth: a sink that stores every line (LogScope keeps debug in the
     * database) would otherwise take one row per attacker request. One line
     * per window still names the address, the pattern and the User-Agent;
     * the rest of the burst is the same facts again.
     *
     * The window is a cache `add()`, on the store the rest of the package
     * uses. A cache that errors skips the line rather than writing it
     * unthrottled: a diagnostic is not worth a log line per request during
     * an outage, and BlockedIpMiddleware already reports the outage itself.
     */
    private function report(string $reason, string $agent, ?string $ip): void
    {
        try {
            $store = config('watchtower.cache.store');
            $prefix = (string) config('watchtower.cache.key', 'watchtower:blacklist');

            if (! Cache::store(is_string($store) ? $store : null)
                ->add($prefix.':ua:logged:'.sha1($reason."\0".$ip), true, self::LOG_WINDOW_SECONDS)) {
                return;
            }

            Log::channel(config('watchtower.log_channel', 'stack'))
                ->debug('Watchtower: rejected a request by User-Agent', [
                    'matched'    => $reason,
                    'user_agent' => $agent,
                    'ip'         => $ip,
                ]);
        } catch (\Throwable) {
            // A broken cache or log channel must not turn a rejection into a 500.
        }
    }
}
