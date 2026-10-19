<?php

declare(strict_types=1);

namespace Watchtower\Services;

use Illuminate\Contracts\Cache\Repository;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Log;
use Watchtower\Events\AccountTargeted;
use Watchtower\Support\FailureWindow;
use Watchtower\Support\IpRange;

/**
 * Credential stuffing, counted by account and by subnet (#180).
 *
 * failed_logins counts per address, and a stuffing run is built to stay
 * under that: each address tries a few logins and moves on. It shows up
 * when the failures are counted the other way round —
 *
 * - `one_account`: distinct addresses failing against one existing account;
 * - `one_subnet`: distinct accounts failed against from one subnet
 *   (IPv4 `ipv4_prefix`, IPv6 `ipv6_block_prefix`).
 *
 * Report-only by design: a crossing fires AccountTargeted and logs
 * MESSAGE, and nothing is blocked or reset — Watchtower blocks addresses,
 * the app decides what an attacked account needs. So there is no mode.
 *
 * `one_account` keys an account by its guard and id, `one_subnet` by the
 * signal log's target hash — both columns the log keeps, so a crossing here
 * and a replay of the log (AccountReplay) name the same account. Each rule keeps a
 * window fixed from its first member that restarts at every crossing, the
 * way HitWindow does, and step() is the one place that says so for both.
 */
final class AccountTargeting
{
    public const MESSAGE = 'Watchtower: account targeted';

    public const RULES = ['one_account', 'one_subnet'];

    private const DEFAULTS = [
        'one_account' => ['count' => 10, 'window_minutes' => 15],
        'one_subnet'  => ['count' => 20, 'window_minutes' => 15],
    ];

    private const DEFAULT_IPV4_PREFIX = 24;

    /** Narrower than a /16 is one network; broader is half a provider. */
    private const MIN_IPV4_PREFIX = 16;

    /**
     * The most members a window holds. Every failed login reads and writes
     * its whole window back, so a count in the thousands would make each
     * one cost that much, on a path an attacker sets the pace of.
     */
    public const MAX_COUNT = 1000;

    /** Whether any rule is on — the listener and the target hash cost nothing otherwise. */
    public static function enabled(): bool
    {
        foreach (self::RULES as $rule) {
            if (self::ruleEnabled($rule)) {
                return true;
            }
        }

        return false;
    }

    /** Whether this rule is on, behind the auto_block master switch like every detector. */
    public static function ruleEnabled(string $rule): bool
    {
        return (bool) config('watchtower.auto_block.enabled', false)
            && (bool) config("watchtower.auto_block.account_targeting.{$rule}.enabled", false);
    }

    /** A count as a window can hold it: at least 2, since 1 fires on every failure. */
    public static function clampCount(int $count): int
    {
        return min(self::MAX_COUNT, max(2, $count));
    }

    /**
     * A rule's count, window and IPv4 prefix, defaulted and clamped the same
     * way for the live count and for a replay.
     *
     * @return array{count: int, window_minutes: int, ipv4_prefix: int}
     */
    public static function settings(string $rule): array
    {
        $settings = (array) config("watchtower.auto_block.account_targeting.{$rule}", []);
        $prefix = (int) ($settings['ipv4_prefix'] ?? self::DEFAULT_IPV4_PREFIX);

        return [
            'count'          => self::clampCount((int) ($settings['count'] ?? self::DEFAULTS[$rule]['count'])),
            'window_minutes' => max(1, (int) ($settings['window_minutes'] ?? self::DEFAULTS[$rule]['window_minutes'])),
            'ipv4_prefix'    => $prefix >= self::MIN_IPV4_PREFIX && $prefix <= 32 ? $prefix : self::DEFAULT_IPV4_PREFIX,
        ];
    }

    /**
     * What a failed login counts as under a rule: the subject whose window it
     * joins, and the member it adds to that window.
     *
     * An IPv6 address counts as its block target, so one client walking its
     * own /64 is one address, not thousands.
     *
     * `one_account` only counts an attempt at an existing account, and
     * keys it by the account's id rather than the hash of what was typed:
     * the app's lookup may fold case and accents the hash doesn't, so
     * `usér@x.com` and `user@x.com` would otherwise split one account's
     * attempts — and its window — in two. An account that doesn't exist
     * can't be taken over, and counting every identifier an attacker types
     * would open a window per guess; `one_subnet` still counts a spray of
     * made-up names.
     *
     * @return array{0: string, 1: string}|null [subject, member], or null when the rule doesn't count it
     */
    public static function keys(string $rule, string $ip, string $targetHash, ?string $targetUserId, ?string $guard, int $ipv4Prefix): ?array
    {
        $canonical = IpRange::canonical($ip);

        if ($canonical === null || ($rule === 'one_account' && $targetUserId === null)) {
            return null;
        }

        if ($rule === 'one_account') {
            return [($guard ?? '').':'.$targetUserId, IpRange::blockTarget($canonical) ?? $canonical];
        }

        $subnet = str_contains($canonical, ':')
            ? IpRange::blockTarget($canonical)
            : IpRange::canonical("{$canonical}/{$ipv4Prefix}");

        return $subnet === null ? null : [$subnet, $targetHash];
    }

    /**
     * One member arriving at a window: opens the window if none is running,
     * adds the member if it is new, and closes the window once it holds
     * $threshold members.
     *
     * Returns [the window to keep, or null once it closed; the members it
     * closed with, member => target user id, or null while it is open].
     *
     * @param  array{expires: int, members: array<string, ?string>}|null  $window
     * @return array{0: array{expires: int, members: array<string, ?string>}|null, 1: array<string, ?string>|null}
     */
    public static function step(?array $window, string $member, ?string $targetUserId, int $now, int $seconds, int $threshold): array
    {
        if ($window === null || $window['expires'] <= $now) {
            $window = ['expires' => $now + $seconds, 'members' => []];
        }

        // "m:" so a member that happens to be all digits stays a string key.
        $window['members']["m:{$member}"] ??= $targetUserId;

        if (count($window['members']) < $threshold) {
            return [$window, null];
        }

        $members = [];

        foreach ($window['members'] as $key => $userId) {
            $members[substr((string) $key, 2)] = $userId;
        }

        return [null, $members];
    }

    /**
     * Count one failed login against every rule that is on.
     *
     * Fails open, as AutoBlockService::record() does: this runs inside the
     * login request, and a cache that is down must not turn a wrong password
     * into a 500. The events go out after, so an app listener that throws
     * surfaces as its own error rather than as a counting failure, and
     * doesn't cost the other rule its count — or its event: every event is
     * dispatched before the first listener error is rethrown.
     */
    public function record(string $ip, string $targetHash, int|string|null $targetUserId, ?string $guard): void
    {
        $events = [];

        try {
            foreach (self::RULES as $rule) {
                if (self::ruleEnabled($rule)) {
                    $events[] = $this->countRule($rule, $ip, $targetHash, $targetUserId === null ? null : (string) $targetUserId, $guard);
                }
            }
        } catch (\Throwable $e) {
            // No early return: a rule that crossed before this one threw has
            // already forgotten its window, so its event is all that's left.
            if (! FailureWindow::isOpen('account_targeting')) {
                FailureWindow::open('account_targeting');

                try {
                    Log::channel(config('watchtower.log_channel', 'stack'))
                        ->error('Watchtower: account targeting failed, letting the login through uncounted', [
                            'error' => $e->getMessage(),
                        ]);
                } catch (\Throwable) {
                    // A broken log channel must not undo the fail-open.
                }
            }
        }

        $failed = null;

        foreach (array_filter($events) as $event) {
            try {
                event($event);
            } catch (\Throwable $e) {
                $failed ??= $e;
            }
        }

        if ($failed !== null) {
            throw $failed;
        }
    }

    /**
     * The crossing this failure made, logged, or null.
     *
     * ⚠️ Read-modify-write, like HitWindow::recordUser(), with no lock. Two
     * concurrent failures can lose a member, and two that both read a
     * window one short of the count can both cross — so a listener may see
     * the same attack reported twice. A lock on the login path would cost
     * more than the precision is worth to a report.
     */
    private function countRule(string $rule, string $ip, string $targetHash, ?string $targetUserId, ?string $guard): ?AccountTargeted
    {
        $settings = self::settings($rule);
        $keys = self::keys($rule, $ip, $targetHash, $targetUserId, $guard, $settings['ipv4_prefix']);

        if ($keys === null) {
            return null;
        }

        [$subject, $member] = $keys;
        $cache = $this->cache();
        $key = (string) config('watchtower.cache.key', 'watchtower:blacklist').":targeted:{$rule}:{$subject}";
        $now = now()->getTimestamp();

        $stored = self::window($cache->get($key));

        [$window, $crossed] = self::step($stored, $member, $targetUserId, $now, $settings['window_minutes'] * 60, $settings['count']);

        if ($window !== null) {
            // A member already in a running window changes nothing, and is
            // what a retrying attacker sends most: no write for it.
            if ($window !== $stored) {
                $cache->put($key, $window, max(1, $window['expires'] - $now));
            }

            return null;
        }

        $cache->forget($key);

        $event = new AccountTargeted(
            $rule,
            $rule === 'one_account' ? (string) $targetUserId : $subject,
            array_map('strval', array_keys((array) $crossed)),
            array_values(array_unique(array_filter((array) $crossed, static fn (?string $id): bool => $id !== null))),
            $rule === 'one_account' ? $guard : null,
            $settings['window_minutes'],
        );

        try {
            Log::channel(config('watchtower.log_channel', 'stack'))->warning(self::MESSAGE, [
                'rule'            => $event->rule,
                'subject'         => $event->subject,
                'count'           => count($event->members),
                'window_minutes'  => $event->windowMinutes,
                'members'         => $event->members,
                'target_user_ids' => $event->targetUserIds,
                'guard'           => $event->guard,
            ]);
        } catch (\Throwable) {
            // The event is the output that matters.
        }

        return $event;
    }

    /**
     * A stored window, or null for anything that isn't one.
     *
     * @return array{expires: int, members: array<string, ?string>}|null
     */
    private static function window(mixed $value): ?array
    {
        if (! is_array($value) || ! is_int($value['expires'] ?? null) || ! is_array($value['members'] ?? null)) {
            return null;
        }

        return $value;
    }

    /** Resolved per call, like HitWindow::cache(). */
    private function cache(): Repository
    {
        $store = config('watchtower.cache.store');

        return Cache::store(is_string($store) ? $store : null);
    }
}
