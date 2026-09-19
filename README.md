# Watchtower for Laravel

[![License](https://img.shields.io/github/license/AhmedMerza/laravel-watchtower?style=flat-square)](LICENSE.md)
[![PHP Version](https://img.shields.io/badge/php-%3E%3D8.2-blue?style=flat-square)](https://php.net)

> **Active blocking and cross-server coordination at the edge of your Laravel app** — block a bad actor in one environment and every other environment sees the block within minutes. No Cloudflare, no AWS WAF, no infrastructure changes. Block over a JSON API standalone, or one-click from any log entry when LogScope is installed.

> **Status — heading to v1.0.** Core IP blocking, cross-environment push/pull sync, the cache abstraction (works on **any** Laravel cache driver — Redis is no longer required), and the opt-in auto-block engine (with `block` / `warn` / `disabled` modes) are all in place and tested. LogScope is optional: you need it for one-click blocking from its log detail panel, and for the auto-block engine, which reads LogScope's log table.
>
> Still landing before `v1.0.0`: a **standalone management UI** (today the standalone interface is the JSON API below; LogScope users get the in-panel Block-IP button).

## Quick Start

```bash
composer require ahmedmerza/watchtower
php artisan watchtower:install
```

Add your own IP to `WATCHTOWER_NEVER_BLOCK_IPS` before you block anything — see [Installation](#-installation).

**With LogScope:** a **Block IP** button now appears in your LogScope detail panel whenever a log entry has an IP address.

<a id="standalone-no-logscope"></a>**Standalone (no LogScope):** a JSON management API mounts at `/watchtower/api/...` (configurable via `WATCHTOWER_ROUTE_PREFIX`) — `POST /api/block`, `DELETE /api/block/{ip}`, `GET /api/status/{ip}`, `GET /api/blocks`. There is no standalone HTML UI yet (that's coming before v1.0 — see the status note above); standalone, you drive blocks through this API.

**The API is closed outside `local` until you open it.** Access goes through a `viewWatchtower` Gate, which by default allows everyone in the `local` environment and no one anywhere else — the same model as Horizon and Pulse. Define it in your `AppServiceProvider` to decide who gets in:

```php
use Illuminate\Support\Facades\Gate;

public function boot(): void
{
    Gate::define('viewWatchtower', fn ($user) => in_array($user->email, [
        'admin@example.com',
    ]));
}
```

A Gate whose callback needs a `$user` refuses guests, so the routes need a session: keep `web` in `routes.middleware` (the default). That list can add middleware, such as `auth` or a throttle, but the Gate check is always applied after it. A refused request gets a 403, never a redirect. To turn the API off entirely, set `WATCHTOWER_ROUTES_ENABLED=false`. With LogScope installed, LogScope's own authorization applies instead and `viewWatchtower` isn't used.

---

## How It Works

```
Admin blocks an IP from LogScope's UI or the API (staging)
    │
    ├─► DB row created + cache rebuilt → staging protected immediately
    │
    └─► Queued job pushes block to master env
            │
            └─► Every other env pulls from master via watchtower:sync (every 5 min)
                    └─► Cache rebuilt → all environments protected
```

Every incoming request is checked against Laravel's cache (Redis, Memcached, file, database — your choice via `WATCHTOWER_CACHE_STORE`) right after `TrustProxies`, before sessions, auth or routing run. The blocklist table itself is never queried per request. A block can be a single IP or a CIDR range; see [IP Ranges and IPv6](#ip-ranges-and-ipv6).

---

## Table of Contents

- [Requirements](#-requirements)
- [Installation](#-installation)
- [Configuration](#%EF%B8%8F-configuration)
- [Cross-Environment Sync](#-cross-environment-sync)
- [Auto-Block Rules](#-auto-block-rules)
- [Artisan Commands](#-artisan-commands)
- [Security Notes](#-security-notes)
- [Contributing](#-contributing)
- [License](#-license)

---

## 📋 Requirements

- PHP 8.2, 8.3 or 8.4
- Laravel 12 or 13 — both are exercised by CI, and `composer.json` won't install on a major that isn't. Laravel 13 itself requires PHP 8.3+. Laravel 11 is not supported: it is past security support, so every 11.x release carries an open advisory and a current Composer refuses to install one.
- A configured Laravel cache store (any driver — redis, memcached, file, database, array). Redis is recommended for production.
- [ahmedmerza/logscope](https://github.com/AhmedMerza/laravel-logscope) >= 1.6.1 *(optional — needed for the Block-IP button in its detail panel, and for [auto-block rules](#-auto-block-rules))*. LogScope only started including this package's `watchtower::` partial in 1.6.1; 1.5.2–1.6.0 include the pre-rename `logscope-guard::` one, so the button never renders on those.

---

## 📦 Installation

```bash
composer require ahmedmerza/watchtower
php artisan watchtower:install
```

The install command publishes the config and runs the migration. Add these to your `.env`:

```env
WATCHTOWER_ENABLED=true
WATCHTOWER_NEVER_BLOCK_IPS=127.0.0.1,::1,your.own.ip
```

> **Important:** Add your own IP to `WATCHTOWER_NEVER_BLOCK_IPS` before enabling. You cannot be blocked by an IP or range on this list — it is checked before any block operation, before the cache, and before the DB. On IPv6, list your network (`2001:db8:1:2::/64`) rather than one address: blocking any address blocks its whole /64, and a never-block address protects only itself.

Without LogScope, the management API refuses every request outside `local` until you define the `viewWatchtower` Gate — see [Standalone](#standalone-no-logscope).

---

## ⚙️ Configuration

```env
# Master switch
WATCHTOWER_ENABLED=true

# IPs and CIDR ranges that can never be blocked (comma-separated) — prevents self-lockout
WATCHTOWER_NEVER_BLOCK_IPS=127.0.0.1,::1,10.0.0.0/8

# Blocking one IPv6 address blocks the network around it, this many bits long (32–128; 128 = exact address only)
WATCHTOWER_IPV6_BLOCK_PREFIX=64

# Cache store for the blocklist. Blank = your app's default cache store.
# Any Laravel driver works: redis, memcached, file, database, array, dynamodb.
WATCHTOWER_CACHE_STORE=

# Management routes (standalone mode)
WATCHTOWER_ROUTES_ENABLED=true
WATCHTOWER_ROUTE_PREFIX=watchtower
# WATCHTOWER_ROUTE_DOMAIN=admin.example.com

# Cross-environment sync
WATCHTOWER_MASTER_URL=https://your-master-app.com
WATCHTOWER_SYNC_SECRET=a-long-random-secret
WATCHTOWER_SYNC_TOLERANCE=300   # seconds a signed request stays valid

# Auto-block engine (disabled by default)
WATCHTOWER_AUTO_BLOCK_ENABLED=false
WATCHTOWER_AUTO_BLOCK_MODE=warn    # warn (default) | block | disabled
WATCHTOWER_AUTO_BLOCK_DURATION=60
WATCHTOWER_SHARED_IP_USER_THRESHOLD=3   # distinct signed-in users before a block downgrades to a warning; 0 disables
WATCHTOWER_NEVER_AUTO_BLOCK_IPS=        # automation skips these; an admin can still block them by hand

# Webhook notification on every block (optional — useful for n8n, Slack, WhatsApp)
WATCHTOWER_WEBHOOK_URL=
WATCHTOWER_NOTIFICATION_QUEUE=default

# Dedicated log channel for Watchtower events (sync failures, auto-block skips, etc.)
WATCHTOWER_LOG_CHANNEL=stack

# Automatic cleanup of expired temporary blocks (runs daily)
WATCHTOWER_CLEANUP_ENABLED=true
```

### Block Response

By default, blocked IPs receive a plain-text `403 Access denied.` response. It's returned directly, so the app's exception handler never sees it: no custom `errors/403` page, and no JSON body for API clients. To redirect instead:

```php
// config/watchtower.php
'block_response' => [
    'status'   => 403,
    'message'  => 'Access denied.',
    'redirect' => null, // Set a URL to redirect instead
],
```

### IP Ranges and IPv6

A block can be a single IP or a CIDR range, from the API, the LogScope button, auto-block or sync:

```json
POST /watchtower/api/block
{ "ip": "203.0.113.0/24", "reason": "hosting range" }
```

- **Ranges are stored as their network address**, so `203.0.113.77/24` is stored as `203.0.113.0/24`.
- **One IPv6 address blocks its /64.** An IPv6 client usually controls a whole /64 and can move to another address inside it at will, so blocking `2001:db8:1:2::9` stores and blocks `2001:db8:1:2::/64`. Change the width with `WATCHTOWER_IPV6_BLOCK_PREFIX`. To block exactly one IPv6 address, send it as `/128`.
- **Very broad ranges need `force`.** IPv4 ranges shorter than /16 and IPv6 ranges shorter than /32 get a 422 unless the request also sends `force=true`. A master accepts whatever its satellites push, since they already made that call.
- **`WATCHTOWER_NEVER_BLOCK_IPS` accepts ranges** and always wins: an address it covers gets through even when a blocked range covers it too. A block is refused only when the never-block list covers all of it.
- **Unblocking an IP lifts its own block**, including the /64 that blocking it created, but never a wider range that covers it. `DELETE /api/block/{ip}` and `GET /api/status/{ip}` take a range too (`/api/block/203.0.113.0/24`), and the status of an IP names the range blocking it.

Single IPs, and IPv6 networks at the configured prefix (which is everything auto-block creates), are one cache key each. Every other range sits in one list that each request reads, so a request makes two cache reads however many blocks there are.

### Webhook Notification

With `WATCHTOWER_WEBHOOK_URL` set, every block made on this environment — manual, auto-block, or a block a satellite pushes to this master — is posted to that URL as JSON from a queued listener. Blocks a satellite pulls with `watchtower:sync` don't trigger it, so each block is announced once, by the environment that received it.

```json
{
  "ip": "203.0.113.50",
  "reason": "credential stuffing",
  "source": "manual",
  "source_env": "production",
  "blocked_by": "admin@example.com",
  "expires_at": null,
  "blocked_at": "2026-09-17T08:00:00+00:00"
}
```

`source` is `manual`, `auto` or `sync`, and `expires_at` is `null` for a permanent block. The request is unsigned and isn't retried: a connection failure is logged on `WATCHTOWER_LOG_CHANNEL`, and an error response is ignored.

---

## 🌐 Cross-Environment Sync

Watchtower supports a **master/satellite** topology. One environment (production) is the master. Others (staging, alpha) pull from it.

### Setup

**On every environment** (master + satellites), add to `.env`:

```env
WATCHTOWER_MASTER_URL=https://your-production-app.com
WATCHTOWER_SYNC_SECRET=same-secret-on-all-environments
```

That's the whole setup — there are no routes to hand-write. Watchtower registers
the two the sync protocol uses, `GET /watchtower/sync/blocks` and
`POST /watchtower/sync/block`, and authenticates them with the shared secret.

The paths are fixed, not affected by `WATCHTOWER_ROUTE_PREFIX`: the satellite
signs the path it calls, so both ends have to agree on it. They're also outside
the `web` middleware group — no session, no CSRF — because they're
machine-to-machine.

> ⚠️ **The secret is a credential, and it is fleet-wide.** Anyone holding it can
> block any IP on every environment at once, and read any environment's
> blocklist. Use a long random value, keep it out of version control, and rotate
> it on all environments together.

**The routes come up wherever the secret is set — including satellites.**
Registration is gated on `WATCHTOWER_SYNC_SECRET` alone, and satellites need
that secret to sign their own requests, so they serve the endpoints too. Since
the secret is the same everywhere, this grants a holder nothing they didn't
already have, but it is more surface than a satellite strictly needs. An
environment with no secret exposes nothing. Per-environment keys, which would
let a satellite sign without also serving, are tracked in
[#36](https://github.com/AhmedMerza/laravel-watchtower/issues/36).

> ⚠️ **Keep your satellites out of the blocklist.** The blocking middleware is
> global, so it runs on the sync routes as well. If the master ever blocks a
> satellite's egress IP — an auto-block rule matching its traffic, or a manual
> mistake — that satellite stops syncing in both directions and `watchtower:sync`
> just reports `HTTP 403`. Add your satellites' egress IPs to
> `WATCHTOWER_NEVER_BLOCK_IPS` on the master.

**On satellites**, schedule the sync command:

```php
// routes/console.php
use Illuminate\Support\Facades\Schedule;

Schedule::command('watchtower:sync')->everyFiveMinutes();
```

### How Push + Pull Work Together

| Direction | Trigger | Speed |
|-----------|---------|-------|
| **Push** (satellite → master) | Every `BlacklistService::block()` call | Immediate (queued job) |
| **Pull** (master → satellites) | `watchtower:sync` schedule | Every 5 min (configurable) |

Block on staging → staging protected instantly → master updated asynchronously → production/alpha pull it within 5 minutes.

---

## 🤖 Auto-Block Rules

Automatically block IPs based on patterns in LogScope's log table (`logscope.table`, default `log_entries`), so auto-block needs LogScope installed ([#23](https://github.com/AhmedMerza/laravel-watchtower/issues/23) tracks rules that work without it). Disabled by default, and ships with an **empty `rules` array** — you opt in by defining rules yourself.

> ⚠️ **Tune carefully or lock real users out.** An overly broad rule can block legitimate traffic across every environment. **A new rule is a dry run by default** — it reports what it would have caught and blocks nobody until you arm it.

```env
WATCHTOWER_AUTO_BLOCK_ENABLED=true
WATCHTOWER_AUTO_BLOCK_MODE=warn    # warn (default) | block | disabled
WATCHTOWER_AUTO_BLOCK_DURATION=60  # minutes
WATCHTOWER_SHARED_IP_USER_THRESHOLD=3
WATCHTOWER_NEVER_AUTO_BLOCK_IPS=203.0.113.0/24
```

**Modes** (global default, overridable per rule):

| Mode | Behaviour |
|------|-----------|
| `warn` | **The default.** Match the rule and emit a structured `would_have_blocked: true` log entry on the configured log channel — but **do not** block. Tail your logs for that key to see what the rule would catch, then set `WATCHTOWER_AUTO_BLOCK_MODE=block` to arm it. |
| `block` | Actually block matching IPs. |
| `disabled` | Skip the rule entirely. A per-rule kill switch without deleting the definition. |

### Shared IPs

Plenty of real users share one public address: mobile carriers put subscribers behind carrier-grade NAT, and offices, universities and VPN exits do the same. Count errors per IP and a rule tuned to catch **one** bad actor ends up blocking **everyone** behind that gateway.

So before it blocks, watchtower counts how many **distinct signed-in users** the log saw from that address during the window. At or above `WATCHTOWER_SHARED_IP_USER_THRESHOLD` (default `3`) the block downgrades to a warning carrying `not_blocked_because: shared IP`. Set the threshold to `0` to switch the guard off.

The count covers **all** of the address's logged traffic, not just the rows the rule matched — the question is how many people a block would hit, not how many of them tripped it. An address where one buggy client throws every error while two hundred others browse fine is the case this exists for.

Two limits worth knowing:

- It only sees users your app actually logged. It protects an address your users are signed in from; it can't recognise a busy gateway whose traffic is all anonymous.
- Anonymous traffic counts for nobody, so a scanner hitting you while signed out still gets blocked. That is deliberate.

For gateways the guard can't see, list them explicitly:

```env
WATCHTOWER_NEVER_AUTO_BLOCK_IPS=203.0.113.0/24,2001:db8:2::/48
```

`never_auto_block` binds automation only — **an admin can still block a listed address by hand**, through the UI or the API. That is the whole difference from `never_block`, which nothing can override. Use `never_auto_block` for "a rule would be right about this traffic and wrong about the people behind it", and `never_block` for "never, under any circumstances".

Define rules in `config/watchtower.php`:

```php
'auto_block' => [
    'enabled'                  => env('WATCHTOWER_AUTO_BLOCK_ENABLED', false),
    'mode'                     => env('WATCHTOWER_AUTO_BLOCK_MODE', 'warn'),
    'shared_ip_user_threshold' => (int) env('WATCHTOWER_SHARED_IP_USER_THRESHOLD', 3),
    'block_duration_minutes'   => 60,
    'rules' => [
        // Armed: block IPs that generate 50+ errors in 5 minutes
        [
            'level'            => 'error',
            'message_contains' => null,
            'count'            => 50,
            'window_minutes'   => 5,
            'mode'             => 'block',
        ],
        // Still a dry run — no 'mode', so it follows the 'warn' default
        [
            'level'            => 'warning',
            'message_contains' => '404',
            'count'            => 100,
            'window_minutes'   => 10,
        ],
    ],
],
```

Rules run every minute via the scheduler. Add the scheduler to your server if not already running:

```bash
* * * * * cd /your-app && php artisan schedule:run >> /dev/null 2>&1
```

> **Note:** IPs in `WATCHTOWER_NEVER_BLOCK_IPS` are never auto-blocked, even if they match a rule. Those in `WATCHTOWER_NEVER_AUTO_BLOCK_IPS` are skipped by automation but remain blockable by hand.

---

## 🔧 Artisan Commands

```bash
# First-time setup (publish config + run migration)
php artisan watchtower:install

# Pull blacklist from master and rebuild the local cache
php artisan watchtower:sync

# Delete expired temporary blocks and rebuild the cache
# Runs automatically every day — set WATCHTOWER_CLEANUP_ENABLED=false to manage manually
# Permanent blocks (no expiry) are never touched
php artisan watchtower:cleanup
```

---

## 🔒 Security Notes

**Trusted proxies:** Watchtower checks `$request->ip()` in a global middleware registered directly after Laravel's `TrustProxies`, so the forwarded client IP has already been resolved. It still runs before sessions, auth and routing. If your app is behind a load balancer or proxy, configure trusted proxies (`$middleware->trustProxies(at: ...)` in `bootstrap/app.php`), otherwise every request looks like it comes from the proxy. If you've removed `TrustProxies` from the global stack, Watchtower runs first and sees the direct peer address.

**Cache outages fail open:** if the cache store throws during the lookup, the request is let through unchecked rather than returning a 500. The failure is logged on `watchtower.log_channel` roughly once a minute, and the cache warm-up stands down for the same window, so an outage can't fill the disk with one log line per request. The throttle window is kept in marker files under `storage/framework/`; on a read-only filesystem it degrades to per-process throttling. The check isn't atomic, so requests already in flight when an outage starts can each log once before the window closes — expect a small burst at onset, then one line per minute.

**HMAC signatures:** Sync requests are signed by the satellite and verified by the master. The signature is `hash_hmac('sha256', timestamp + METHOD + path + rawBody, WATCHTOWER_SYNC_SECRET)`, sent as `X-Watchtower-Signature` alongside `X-Watchtower-Timestamp`; `Watchtower\Support\SyncSignature` is the one implementation both ends use. The master compares with `hash_equals` and rejects anything unsigned, wrongly signed, or carrying a timestamp more than `sync.timestamp_tolerance` seconds (default 300) from its own clock, which bounds how long a captured request stays replayable. Method and path are inside the signed string, so a captured read can't be replayed as a write. Use a long, random secret and keep it identical across environments.

**Cache TTL:** Each per-IP cache entry carries a 24-hour TTL (configurable via `cache.ttl_hours`) as a safety net. The cache is explicitly rebuilt on every block/unblock and on `watchtower:sync`; if the store is flushed or its entries expire, the next lookup warms it from the DB.

---

## 🤝 Contributing

Contributions are welcome. Please open an issue or submit a pull request on [GitHub](https://github.com/AhmedMerza/laravel-watchtower).

---

## 📄 License

MIT License. See [LICENSE](LICENSE.md) for details.
