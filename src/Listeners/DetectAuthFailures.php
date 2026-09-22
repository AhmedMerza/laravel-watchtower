<?php

declare(strict_types=1);

namespace Watchtower\Listeners;

use Illuminate\Auth\Events\Failed;
use Illuminate\Auth\Events\Lockout;
use Illuminate\Http\Request;
use Watchtower\Http\Middleware\BlockedIpMiddleware;
use Watchtower\Services\AutoBlockService;

/**
 * The two detectors that read Laravel's own auth events.
 *
 * - `failed_logins` counts `Auth\Events\Failed`, which every guard fires on
 *   a bad credential — no log table, no package integration.
 * - `login_lockouts` counts `Auth\Events\Lockout`, fired by the login
 *   throttle Breeze, Fortify and ThrottlesLogins already use. Counting it
 *   builds on a limit the app has set for itself: one lockout is a user
 *   fumbling a password, several is someone working through a list.
 *
 * Neither reports a user id to the shared-IP guard, deliberately — see
 * record().
 */
class DetectAuthFailures
{
    public function __construct(private readonly AutoBlockService $autoBlock) {}

    public function handleFailed(Failed $event): void
    {
        $this->record('failed_logins', request());
    }

    public function handleLockout(Lockout $event): void
    {
        $this->record('login_lockouts', $event->request);
    }

    /**
     * Count the signal, with no user attached.
     *
     * `Failed::$user` is tempting and wrong. It is the account the
     * credentials were aimed at, not the person at the keyboard — so an
     * attacker working through a list of known usernames would report a new
     * distinct "user" on every attempt, and the shared-IP guard, which
     * downgrades a block once enough distinct users sit behind an address,
     * would read a credential-stuffing run as a busy office and stand down.
     * The guard would be disarmed by precisely the attack it is in the way
     * of.
     *
     * So the guard only ever counts users seen on a request that actually
     * authenticated, which a failed login by definition is not. For an
     * address whose traffic is all anonymous it is blind — the same gap the
     * log-based guard documents — and never_auto_block is the answer for a
     * known office or carrier range.
     */
    private function record(string $detector, ?Request $request): void
    {
        $ip = $request === null ? null : BlockedIpMiddleware::clientIp($request);

        // No request behind the event (a console login, a queued job).
        if ($ip === null) {
            return;
        }

        // These fire inside the route, so BlockedIpMiddleware has already
        // run and its verdict is on the request — see its BLOCKED constant.
        $this->autoBlock->record($detector, $ip, null, BlockedIpMiddleware::verdict($request));
    }
}
