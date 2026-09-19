<?php

return [

    /*
    |--------------------------------------------------------------------------
    | Enable Watchtower
    |--------------------------------------------------------------------------
    |
    | Master switch. When false, the blocking middleware passes all requests
    | through and no blocks are enforced.
    |
    */

    'enabled' => env('WATCHTOWER_ENABLED', env('GUARD_ENABLED', true)),

    /*
    |--------------------------------------------------------------------------
    | Routes
    |--------------------------------------------------------------------------
    |
    | Where Watchtower mounts its management API. When LogScope is also
    | installed, routes mount under LogScope's prefix as `<prefix>/watchtower`
    | and use LogScope's authorization. When running standalone, routes mount
    | at the prefix below, behind the middleware list here.
    |
    | Standalone access is decided by the `viewWatchtower` Gate, which only
    | allows the `local` environment until you define it yourself, e.g. in
    | AppServiceProvider::boot():
    |
    |   Gate::define('viewWatchtower', fn ($user) => $user->isAdmin());
    |
    | The Gate check always runs after `middleware`, so this list can add to
    | it (e.g. 'auth') but can't remove it. Keep 'web' so the Gate can see
    | the logged-in user. Set `enabled` => false to turn the routes off.
    |
    */

    'routes' => [
        'enabled'    => env('WATCHTOWER_ROUTES_ENABLED', true),
        'prefix'     => env('WATCHTOWER_ROUTE_PREFIX', 'watchtower'),
        'domain'     => env('WATCHTOWER_ROUTE_DOMAIN'),
        'middleware' => ['web'],
    ],

    /*
    |--------------------------------------------------------------------------
    | Cache
    |--------------------------------------------------------------------------
    |
    | Watchtower checks blocked IPs against Laravel's cache on every request
    | so the request path is one cache lookup with no DB hit. Any cache
    | driver Laravel supports works: redis, memcached, file, database,
    | array, dynamodb. Redis is recommended for production (lowest
    | request-time latency); file is fine for low-volume single-server
    | deployments.
    |
    | 'store'      - The cache store to use. null (default) = your
    |                application's default cache store (config/cache.php
    |                → 'default'). Set to a specific store name (e.g.
    |                'redis', 'file') to override per-package without
    |                touching cache.default.
    |
    |                If you want a SEPARATE Redis connection just for
    |                Watchtower, define a custom cache store in
    |                config/cache.php and set WATCHTOWER_CACHE_STORE to
    |                its name. Example:
    |
    |                    // config/cache.php
    |                    'stores' => [
    |                        'watchtower' => [
    |                            'driver' => 'redis',
    |                            'connection' => 'watchtower-redis',
    |                        ],
    |                    ],
    |
    | 'key'        - Cache key prefix. Single IPs and IPv6 networks at
    |                `ipv6_block_prefix` land at `{key}:ip:{target}`,
    |                every other range in `{key}:_ranges`, and the
    |                index sidecar at `{key}:_index`. Enabled detectors
    |                also count per IP at `{key}:hits:{detector}:{ip}`
    |                and remember signed-in users at
    |                `{key}:users:{detector}:{ip}`, both decaying with
    |                the detector's own window. Change the prefix only
    |                if it conflicts with another package's cache keys.
    |
    | 'ttl_hours'  - Safety-net TTL on every cache entry. The cache is
    |                explicitly rebuilt on every block/unblock and on
    |                watchtower:sync, so the TTL is a backstop for the
    |                rare case where the rebuild silently failed (e.g.
    |                DB unavailable mid-flush).
    |
    */

    'cache' => [
        'store'     => env('WATCHTOWER_CACHE_STORE'),
        'key'       => 'watchtower:blacklist',
        'ttl_hours' => 24,
    ],

    /*
    |--------------------------------------------------------------------------
    | Block Response
    |--------------------------------------------------------------------------
    |
    | What to return when a blocked IP hits your app. Set 'redirect' to a URL
    | to redirect instead of returning a plain response.
    |
    */

    'block_response' => [
        'status'   => 403,
        'message'  => 'Access denied.',
        'redirect' => null,
    ],

    /*
    |--------------------------------------------------------------------------
    | Never-Block Whitelist
    |--------------------------------------------------------------------------
    |
    | IPs and CIDR ranges that can never be blocked by any means — UI,
    | auto-block, or sync. They win over any block that covers them, so this
    | prevents self-lockout. Populate via env (comma-separated) or directly.
    |
    | Entries match as written: an IPv6 address here protects only itself,
    | even though blocking a neighbour blocks its whole /64 (see below). To
    | keep an IPv6 network reachable, list its range.
    |
    | Example .env: WATCHTOWER_NEVER_BLOCK_IPS=127.0.0.1,::1,10.0.0.0/8,2001:db8:1::/64
    |
    */

    'never_block' => array_filter(
        array_map('trim', explode(',', env('WATCHTOWER_NEVER_BLOCK_IPS', env('GUARD_NEVER_BLOCK_IPS', '127.0.0.1,::1'))))
    ),

    /*
    |--------------------------------------------------------------------------
    | Never Auto-Block
    |--------------------------------------------------------------------------
    |
    | Addresses and ranges that automation leaves alone. Unlike never_block,
    | these are not protected from you: an admin can still block one by hand,
    | through the UI or the API. Use it where a rule would be right about the
    | traffic and wrong about the people behind it — an office gateway, a VPN
    | exit, a mobile carrier's NAT pool.
    |
    | A listed address that crosses a rule threshold is recorded as a
    | would-have-blocked warning instead of being blocked.
    |
    | Example .env: WATCHTOWER_NEVER_AUTO_BLOCK_IPS=203.0.113.0/24,2001:db8:2::/48
    |
    */

    'never_auto_block' => array_filter(
        array_map('trim', explode(',', (string) env('WATCHTOWER_NEVER_AUTO_BLOCK_IPS', '')))
    ),

    /*
    |--------------------------------------------------------------------------
    | IPv6 Block Prefix
    |--------------------------------------------------------------------------
    |
    | An IPv6 client usually controls a whole /64 and can move to another
    | address inside it whenever it likes, so blocking a single IPv6 address
    | blocks the network around it, this many bits long. Between 32 and 128;
    | anything else falls back to 64. 128 blocks exact addresses only.
    |
    | An explicit range is blocked as written, so 2001:db8::1/128 still
    | blocks just that one address.
    |
    */

    'ipv6_block_prefix' => (int) env('WATCHTOWER_IPV6_BLOCK_PREFIX', 64),

    /*
    |--------------------------------------------------------------------------
    | Auto-Block Engine
    |--------------------------------------------------------------------------
    |
    | Automatically block IPs that match log-based rules. Disabled by default.
    | Rules are evaluated every minute via the scheduler.
    |
    | Mode (global default — overrideable per rule):
    |   'warn'     - THE DEFAULT. Match the rule and emit a structured
    |                `would_have_blocked` log entry on the configured
    |                `log_channel`, but do NOT block. A new rule starts as a
    |                dry run: tail your logs (or query LogScope) for
    |                `would_have_blocked: true` to see what it WOULD catch
    |                before letting it lock anyone out. Once you trust the
    |                rule, set WATCHTOWER_AUTO_BLOCK_MODE=block to arm it.
    |   'block'    - actually block matching IPs.
    |   'disabled' - skip the rule entirely. Useful as a per-rule kill switch
    |                without removing the rule definition.
    |
    | Shared-IP guard (applies in 'block' mode):
    |   Many real users share one public address — mobile carriers put
    |   subscribers behind carrier-grade NAT, and offices, universities and
    |   VPN exits do the same. A rule tuned to catch one bad actor would
    |   block everyone behind that gateway. So before blocking, watchtower
    |   counts how many DISTINCT authenticated users the log saw from the
    |   address across the window — all of its traffic, not just the rows
    |   the rule matched, because the point is how many people a block would
    |   hit. At or above shared_ip_user_threshold it downgrades to a warning
    |   and records `not_blocked_because: shared IP`. Set it to 0 to switch
    |   the guard off.
    |
    |   This can only see users the app actually logged. It protects an
    |   address your users are signed in from; it can't recognise a busy
    |   gateway whose traffic is all anonymous. List those in
    |   never_auto_block above.
    |
    | Rule shape:
    |   level            - log level to match (e.g. 'error', 'warning'). Null = any.
    |   message_contains - substring match on log message. Null = any.
    |   count            - number of matching logs within the window to trigger a block.
    |   window_minutes   - look-back window for counting logs.
    |   mode             - (optional) override the global mode for this rule only.
    |
    | Detectors (below) are the other half of the engine. Rules read a log
    | table on a schedule; detectors react to Laravel's own signals as they
    | happen, so they need no log table and no LogScope, and they act within
    | the request rather than up to a minute later. They share every guard
    | with rules: mode, the shared-IP threshold, and never_auto_block.
    |
    | Each is OFF by default. Counting happens per IP in the cache, and an
    | address only gets a counter once it has done something a detector
    | counts — traffic that matches nothing writes nothing.
    |
    | Detector shape:
    |   enabled        - off by default. Turn one on at a time.
    |   count          - signals within the window before it fires.
    |   window_minutes - how long the counter decays over.
    |   mode           - (optional) override the global mode for this
    |                    detector only.
    |
    | ⚠️ The shared-IP guard is blind to anonymous traffic, and the auth
    | detectors are anonymous by nature — a failed login has no signed-in
    | user, and the account the credentials were aimed at is not the person
    | at the keyboard, so it is deliberately NOT counted (an attacker
    | working through a username list would otherwise look like a busy
    | office and stand the guard down). Put known office, campus and carrier
    | ranges in never_auto_block before arming failed_logins or
    | login_lockouts.
    |
    */

    'auto_block' => [
        'enabled'                  => env('WATCHTOWER_AUTO_BLOCK_ENABLED', env('GUARD_AUTO_BLOCK_ENABLED', false)),
        'mode'                     => env('WATCHTOWER_AUTO_BLOCK_MODE', 'warn'),
        // Not cast here: 0 means "guard off", and a bare (int) would turn a
        // blank or misspelled value into 0 too. The service parses it and
        // falls back to the default, loudly, when it isn't a whole number.
        'shared_ip_user_threshold' => env('WATCHTOWER_SHARED_IP_USER_THRESHOLD', 3),
        'block_duration_minutes'   => env('WATCHTOWER_AUTO_BLOCK_DURATION', env('GUARD_AUTO_BLOCK_DURATION', 60)),
        'rules'                    => [
            // Example — a rule you're still tuning. With no 'mode' it runs
            // in warn mode, the global default:
            // [
            //     'level'            => 'error',
            //     'message_contains' => null,
            //     'count'            => 50,
            //     'window_minutes'   => 5,
            // ],
            //
            // Example — the same rule, armed, once the warnings look right:
            // [
            //     'level'            => 'error',
            //     'message_contains' => null,
            //     'count'            => 50,
            //     'window_minutes'   => 5,
            //     'mode'             => 'block',
            // ],
        ],

        'detectors' => [

            // Illuminate\Auth\Events\Failed — fired by every guard on a bad
            // credential. 10 in 5 minutes is well clear of a person
            // mistyping a password twice, and still catches a list being
            // worked through at any pace worth blocking.
            'failed_logins' => [
                'enabled'        => env('WATCHTOWER_DETECT_FAILED_LOGINS', false),
                'count'          => 10,
                'window_minutes' => 5,
            ],

            // Illuminate\Auth\Events\Lockout — fired by the login throttle
            // Breeze, Fortify and ThrottlesLogins already apply, so this
            // builds on a limit the app has set for itself. One lockout is
            // someone fumbling a password; three in a quarter of an hour is
            // someone working through a list.
            'login_lockouts' => [
                'enabled'        => env('WATCHTOWER_DETECT_LOGIN_LOCKOUTS', false),
                'count'          => 3,
                'window_minutes' => 15,
            ],

            // Paths no legitimate client asks for, which is why the
            // threshold is 1: a single request for /.env is not a mistake.
            //
            // ⚠️ A threshold of 1 means ONE request is enough to block an
            // address, with no accumulation to ride out a mistake. That puts
            // the whole weight on `$request->ip()` being the real client: a
            // proxy or load balancer that forwards a client-supplied
            // X-Forwarded-For verbatim lets an attacker name an innocent
            // address and have it blocked with a single crafted request.
            // Watchtower warns when TrustProxies is missing from the stack
            // entirely, but it cannot see an overly-permissive one. Get
            // proxy trust right before arming this.
            // Matching runs against the DECODED path, so /%2Eenv is caught
            // too. Keep this list to paths that are unambiguous — a pattern
            // that overlaps a real route of yours will block the people
            // using it, and the matched request is answered rather than
            // served.
            'scanner_paths' => [
                'enabled'        => env('WATCHTOWER_DETECT_SCANNER_PATHS', false),
                'count'          => 1,
                'window_minutes' => 5,
                'patterns'       => [
                    '/.env',
                    '/.env.*',
                    '/.git/*',
                    '/wp-login.php',
                    '/wp-admin/*',
                    '/xmlrpc.php',
                    '/phpmyadmin*',
                ],
            ],

            // A burst of 404s or 429s is what path enumeration looks like
            // when it isn't using a known filename. Read after the response
            // is sent, so it costs the request nothing.
            //
            // The loosest detector here, and the one most likely to catch a
            // real person: a broken deploy that 404s its own assets can trip
            // it. Leave it in warn mode for a full traffic cycle before
            // arming it, and raise the count if your own logs say so.
            'response_bursts' => [
                'enabled'        => env('WATCHTOWER_DETECT_RESPONSE_BURSTS', false),
                'count'          => 40,
                'window_minutes' => 1,
                'statuses'       => [404, 429],
            ],
        ],
    ],

    /*
    |--------------------------------------------------------------------------
    | Cross-Environment Sync
    |--------------------------------------------------------------------------
    |
    | Configure the master environment URL and shared HMAC secret.
    | The 'watchtower:sync' command pulls the full blacklist from master and
    | rebuilds the local Redis cache.
    |
    | Run on a schedule on satellite environments (e.g. every 5 minutes):
    |   $schedule->command('watchtower:sync')->everyFiveMinutes();
    |
    | 'secret' does double duty. Satellites sign with it; on the master it is
    | also what registers the sync routes and authenticates callers. Set the
    | same long random value on every environment, and treat it like a
    | password: anyone holding it can block any IP everywhere.
    |
    | 'timestamp_tolerance' - how far a request's signed timestamp may sit
    |                from the master's clock, in seconds. Bounds the window in
    |                which a captured request can be replayed, so keep it
    |                short; raise it only if your environments' clocks drift.
    |
    */

    'sync' => [
        'master_url'          => env('WATCHTOWER_MASTER_URL', env('GUARD_MASTER_URL')),
        'secret'              => env('WATCHTOWER_SYNC_SECRET', env('GUARD_SYNC_SECRET')),
        'timestamp_tolerance' => (int) env('WATCHTOWER_SYNC_TOLERANCE', 300),
    ],

    /*
    |--------------------------------------------------------------------------
    | Notifications
    |--------------------------------------------------------------------------
    |
    | Fired (always queued) when any IP is blocked. Post to a webhook —
    | useful for n8n, Slack, or WhatsApp automations.
    |
    */

    'notifications' => [
        'webhook_url' => env('WATCHTOWER_WEBHOOK_URL', env('GUARD_WEBHOOK_URL')),
        'queue'       => env('WATCHTOWER_NOTIFICATION_QUEUE', env('GUARD_NOTIFICATION_QUEUE', 'default')),
    ],

    /*
    |--------------------------------------------------------------------------
    | Log Channel
    |--------------------------------------------------------------------------
    |
    | All Watchtower-related log entries (sync failures, auto-block skips,
    | webhook errors, push job failures) are written to this channel. Defaults
    | to your app's 'stack' channel. Set to a dedicated channel to isolate
    | Watchtower logs.
    |
    | Example .env: WATCHTOWER_LOG_CHANNEL=watchtower
    |
    | Then add a channel to config/logging.php:
    |   'watchtower' => [
    |       'driver' => 'daily',
    |       'path'   => storage_path('logs/watchtower.log'),
    |       'level'  => 'debug',
    |       'days'   => 14,
    |   ],
    |
    */

    'log_channel' => env('WATCHTOWER_LOG_CHANNEL', env('GUARD_LOG_CHANNEL', 'stack')),

    /*
    |--------------------------------------------------------------------------
    | Cleanup
    |--------------------------------------------------------------------------
    |
    | When enabled, Watchtower automatically runs 'watchtower:cleanup' daily
    | to remove expired temporary blocks from the database. Only rows with a past
    | expires_at are deleted — permanent blocks (expires_at = null) are
    | never touched.
    |
    | Set to false if you prefer to schedule or run cleanup manually.
    |
    */

    'cleanup' => [
        'enabled' => env('WATCHTOWER_CLEANUP_ENABLED', env('GUARD_CLEANUP_ENABLED', true)),
    ],

];
