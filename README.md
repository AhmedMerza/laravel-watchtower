# Watchtower for Laravel

[![License](https://img.shields.io/github/license/AhmedMerza/laravel-watchtower?style=flat-square)](LICENSE.md)
[![PHP Version](https://img.shields.io/badge/php-%3E%3D8.2-blue?style=flat-square)](https://php.net)

> **Active blocking and cross-server coordination at the edge of your Laravel app** — block a bad actor in one environment and every other environment sees the block within minutes. No Cloudflare, no AWS WAF, no infrastructure changes. Block over a JSON API standalone, or one-click from any log entry when LogScope is installed.

> **Status — heading to v1.0.** Core IP blocking, cross-environment push/pull sync, the cache abstraction (works on **any** Laravel cache driver — Redis is no longer required), and the opt-in auto-block engine (with `block` / `warn` / `disabled` modes) are all in place and tested. LogScope is fully optional — a dev/suggest dependency you install only if you want one-click blocking from the log detail panel.
>
> Still landing before `v1.0.0`: a **built-in authorization path for standalone installs** (today you wrap the routes in your own auth — see [Standalone](#standalone-no-logscope)) and a **standalone management UI** (today the standalone interface is the JSON API below; LogScope users get the in-panel Block-IP button).

## Quick Start

> **Not on Packagist yet.** Until the first tagged release is published, install from the GitHub repo. Add it as a VCS repository in your app's `composer.json`:
>
> ```json
> "repositories": [
>     { "type": "vcs", "url": "https://github.com/AhmedMerza/laravel-watchtower" }
> ]
> ```
>
> then run `composer require ahmedmerza/watchtower:dev-main`. The commands below assume the package is installed.

**With LogScope:**

```bash
composer require ahmedmerza/watchtower
php artisan watchtower:install
```

A **Block IP** button now appears in your LogScope detail panel whenever a log entry has an IP address.

<a id="standalone-no-logscope"></a>**Standalone (no LogScope):**

```bash
composer require ahmedmerza/watchtower
php artisan watchtower:install
```

A JSON management API mounts at `/watchtower/api/...` (configurable via `WATCHTOWER_ROUTE_PREFIX`) — `POST /api/block`, `DELETE /api/block/{ip}`, `GET /api/status/{ip}`, `GET /api/blocks`. There is no standalone HTML UI yet (that's coming before v1.0 — see the status note above); standalone, you drive blocks through this API. Until v1.1 ships proper standalone auth, wrap the routes in your own auth middleware via `config/watchtower.php` → `routes.middleware` (e.g. `['web', 'auth']` plus a Gate check), or set `WATCHTOWER_ROUTES_ENABLED=false` to disable them entirely.

---

## How It Works

```
Admin blocks IP in LogScope UI (staging)
    │
    ├─► DB row created + cache rebuilt → staging protected immediately
    │
    └─► Queued job pushes block to master env
            │
            └─► Every other env pulls from master via watchtower:sync (every 5 min)
                    └─► Cache rebuilt → all environments protected
```

Every incoming request is checked against Laravel's cache (Redis, Memcached, file, database — your choice via `WATCHTOWER_CACHE_STORE`) before any middleware, session, auth, or route runs. No DB hit per request.

---

## Table of Contents

- [Requirements](#-requirements)
- [Installation](#-installation)
- [Configuration](#%EF%B8%8F-configuration)
- [Cross-Environment Sync](#-cross-environment-sync)
- [Auto-Block Rules](#-auto-block-rules)
- [Artisan Commands](#-artisan-commands)
- [Security Notes](#-security-notes)
- [License](#-license)

---

## 📋 Requirements

- PHP 8.2+
- Laravel 11+
- A configured Laravel cache store (any driver — redis, memcached, file, database, array). Redis is recommended for production.
- [ahmedmerza/logscope](https://github.com/AhmedMerza/laravel-logscope) >= 1.6.1 *(optional — only needed if you want the in-detail-panel Block-IP button)*. LogScope only started including this package's `watchtower::` partial in 1.6.1; 1.5.2–1.6.0 include the pre-rename `logscope-guard::` one, so the button never renders on those.

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

> **Important:** Add your own IP to `WATCHTOWER_NEVER_BLOCK_IPS` before enabling. You cannot be blocked by an IP on this list — it is checked before any block operation, before the cache, and before the DB.

---

## ⚙️ Configuration

```env
# Master switch
WATCHTOWER_ENABLED=true

# IPs that can never be blocked (comma-separated) — prevents self-lockout
WATCHTOWER_NEVER_BLOCK_IPS=127.0.0.1,::1

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
WATCHTOWER_AUTO_BLOCK_MODE=block   # block | warn | disabled
WATCHTOWER_AUTO_BLOCK_DURATION=60

# Webhook notification on every block (optional — useful for n8n, Slack, WhatsApp)
WATCHTOWER_WEBHOOK_URL=
WATCHTOWER_NOTIFICATION_QUEUE=default

# Dedicated log channel for Watchtower events (sync failures, auto-block skips, etc.)
WATCHTOWER_LOG_CHANNEL=stack

# Automatic cleanup of expired temporary blocks (runs daily)
WATCHTOWER_CLEANUP_ENABLED=true
```

### Block Response

By default, blocked IPs receive a plain `403 Access denied.` response. To redirect instead:

```php
// config/watchtower.php
'block_response' => [
    'status'   => 403,
    'message'  => 'Access denied.',
    'redirect' => null, // Set a URL to redirect instead
],
```

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

Automatically block IPs based on log patterns. Disabled by default, and ships with an **empty `rules` array** — you opt in by defining rules yourself.

> ⚠️ **Tune carefully or lock real users out.** An overly broad rule can block legitimate traffic across every environment. Start each new rule in `warn` mode (below), validate it against real traffic, then flip it to `block`.

```env
WATCHTOWER_AUTO_BLOCK_ENABLED=true
WATCHTOWER_AUTO_BLOCK_MODE=block   # block | warn | disabled (global default)
WATCHTOWER_AUTO_BLOCK_DURATION=60  # minutes
```

**Modes** (global default, overridable per rule):

| Mode | Behaviour |
|------|-----------|
| `block` | Actually block matching IPs (production behaviour). |
| `warn` | Match the rule and emit a structured `would_have_blocked: true` log entry on the configured log channel — but **do not** block. Use this to validate a rule against live traffic before trusting it. |
| `disabled` | Skip the rule entirely. A per-rule kill switch without deleting the definition. |

Define rules in `config/watchtower.php`:

```php
'auto_block' => [
    'enabled'                => env('WATCHTOWER_AUTO_BLOCK_ENABLED', false),
    'mode'                   => env('WATCHTOWER_AUTO_BLOCK_MODE', 'block'),
    'block_duration_minutes' => 60,
    'rules' => [
        // Block IPs that generate 50+ errors in 5 minutes
        [
            'level'            => 'error',
            'message_contains' => null,
            'count'            => 50,
            'window_minutes'   => 5,
        ],
        // Same rule, but only warn while you tune it (per-rule mode override)
        [
            'level'            => 'warning',
            'message_contains' => '404',
            'count'            => 100,
            'window_minutes'   => 10,
            'mode'             => 'warn',
        ],
    ],
],
```

Rules run every minute via the scheduler. Add the scheduler to your server if not already running:

```bash
* * * * * cd /your-app && php artisan schedule:run >> /dev/null 2>&1
```

> **Note:** IPs in `WATCHTOWER_NEVER_BLOCK_IPS` are never auto-blocked, even if they match a rule.

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

**Cache outages fail open:** if the cache store throws during the lookup, the request is let through unchecked rather than returning a 500. The failure is logged on `watchtower.log_channel` roughly once a minute, and the boot-time cache warm-up stands down for the same window, so an outage can't fill the disk with one log line per request. The throttle window is kept in marker files under `storage/framework/`; on a read-only filesystem it degrades to per-process throttling. The check isn't atomic, so requests already in flight when an outage starts can each log once before the window closes — expect a small burst at onset, then one line per minute.

**HMAC signatures:** Sync requests are signed by the satellite and verified by the master. The signature is `hash_hmac('sha256', timestamp + METHOD + path + rawBody, WATCHTOWER_SYNC_SECRET)`, sent as `X-Watchtower-Signature` alongside `X-Watchtower-Timestamp`; `Watchtower\Support\SyncSignature` is the one implementation both ends use. The master compares with `hash_equals` and rejects anything unsigned, wrongly signed, or carrying a timestamp more than `sync.timestamp_tolerance` seconds (default 300) from its own clock, which bounds how long a captured request stays replayable. Method and path are inside the signed string, so a captured read can't be replayed as a write. Use a long, random secret and keep it identical across environments.

**Cache TTL:** Each per-IP cache entry carries a 24-hour TTL (configurable via `cache.ttl_hours`) as a safety net. The cache is explicitly rebuilt on every block/unblock and on `watchtower:sync`; if the store is flushed, it warms from the DB automatically on the next request boot.

---

## 🤝 Contributing

Contributions are welcome. Please open an issue or submit a pull request on [GitHub](https://github.com/AhmedMerza/laravel-watchtower).

---

## 📄 License

MIT License. See [LICENSE](LICENSE.md) for details.
