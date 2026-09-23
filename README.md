# Watchtower for Laravel

[![License](https://img.shields.io/github/license/AhmedMerza/laravel-watchtower?style=flat-square)](LICENSE.md)
[![PHP Version](https://img.shields.io/badge/php-%3E%3D8.2-blue?style=flat-square)](https://php.net)

> **Active blocking and cross-server coordination at the edge of your Laravel app** — block a bad actor in one environment and every other environment sees the block within minutes. No Cloudflare, no AWS WAF, no infrastructure changes. Block from the built-in management page, over a JSON API, or one-click from any log entry when LogScope is installed.

> **Status — heading to v1.0.** Core IP blocking, cross-environment push/pull sync, the cache abstraction (works on **any** Laravel cache driver — Redis is no longer required), and the opt-in auto-block engine (with `block` / `warn` / `disabled` modes) are all in place and tested. LogScope is optional: you need it for one-click blocking from its log detail panel, and for the log-based auto-block rules, which read LogScope's log table. The real-time detectors — failed logins, login lockouts, scanner paths and response bursts — work without it.
>
> The **[management page](#%EF%B8%8F-management-page)** ships too, so nothing here needs LogScope to be usable: it lists what is blocked and blocks and unblocks by hand, with no build step and no JavaScript.
>
> Still landing before `v1.0.0`: backtesting a rule against real history before switching it on (`watchtower:simulate`), pushing blocks out to Cloudflare or an nginx deny file rather than only to other Laravel environments, and an importer for anyone migrating off `antonioribeiro/firewall`. The full list, and what is deliberately **not** being built, is in the [roadmap](https://github.com/AhmedMerza/laravel-watchtower/issues/26).

## Quick Start

```bash
composer require ahmedmerza/watchtower
php artisan watchtower:install
```

Add your own IP to `WATCHTOWER_NEVER_BLOCK_IPS` before you block anything — see [Installation](#-installation).

**With LogScope:** a **Block IP** button now appears in your LogScope detail panel whenever a log entry has an IP address.

<a id="standalone-no-logscope"></a>**Standalone (no LogScope):** a JSON management API mounts at `/watchtower/api/...` (configurable via `WATCHTOWER_ROUTE_PREFIX`) — `POST /api/block`, `DELETE /api/block/{ip}`, `GET /api/status/{ip}`, and a paginated, filterable [`GET /api/blocks`](#listing-blocks). A **[management page](#%EF%B8%8F-management-page)** mounts at the same prefix — `/watchtower` — listing what is blocked, with a block form and an unblock that asks first, so the API is for your own scripts rather than the only way in.

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
Admin blocks an IP from the management page, LogScope's UI or the API (staging)
    │
    ├─► DB row created + cache rebuilt → staging protected immediately
    │
    └─► Queued job pushes block to master env
            │
            └─► Every other env pulls from master via watchtower:sync (every 5 min)
                    └─► Cache rebuilt → all environments protected
```

Every incoming request is checked against Laravel's cache (Redis, Memcached, file, database — your choice via `WATCHTOWER_CACHE_STORE`) right after `TrustProxies`, before sessions, auth or routing run. The blocklist table itself is never queried per request. A block can be a single IP or a CIDR range; see [IP Ranges and IPv6](#ip-ranges-and-ipv6). Requests that get past the blocklist are also checked against a short list of [attack-tool User-Agents](#%EF%B8%8F-attack-tool-user-agents).

---

## Table of Contents

- [Requirements](#-requirements)
- [Installation](#-installation)
- [Upgrading](#%EF%B8%8F-upgrading)
- [Configuration](#%EF%B8%8F-configuration)
- [Management Page](#%EF%B8%8F-management-page)
- [Cross-Environment Sync](#-cross-environment-sync)
- [Attack-Tool User-Agents](#%EF%B8%8F-attack-tool-user-agents)
- [Auto-Block](#-auto-block)
- [Scoped Blocks](#-scoped-blocks)
- [Artisan Commands](#-artisan-commands)
- [Security Notes](#-security-notes)
- [Contributing](#-contributing)
- [License](#-license)

---

## 📋 Requirements

- PHP 8.2, 8.3 or 8.4
- Laravel 12 or 13 — both are exercised by CI, and `composer.json` won't install on a major that isn't. Laravel 13 itself requires PHP 8.3+. Laravel 11 is not supported: it is past security support, so every 11.x release carries an open advisory and a current Composer refuses to install one.
- A configured Laravel cache store (any driver — redis, memcached, file, database, array). Redis is recommended for production.
- [ahmedmerza/logscope](https://github.com/AhmedMerza/laravel-logscope) >= 1.6.1 *(optional — needed for the Block-IP button in its detail panel, and for [log-based auto-block rules](#log-rules); the [detectors](#detectors) need no LogScope)*. LogScope only started including this package's `watchtower::` partial in 1.6.1; 1.5.2–1.6.0 include the pre-rename `logscope-guard::` one, so the button never renders on those.

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

Without LogScope, the management page and API both refuse every request outside `local` until you define the `viewWatchtower` Gate — see [Standalone](#standalone-no-logscope).

---

## ⬆️ Upgrading

Upgrading an existing install needs three things, plus one more if you read the API from a script. Each is covered in full in the [CHANGELOG](CHANGELOG.md); this is the short version.

**1. Run the migrations.** Recent releases added the `scope` column on `blacklisted_ips` and the `ip_offences` table that escalating durations use:

```bash
# only if you publish migrations — re-publish so the new ones land
php artisan vendor:publish --tag=watchtower-migrations

php artisan migrate
```

⚠️ Rolling the `scope` migration *back* fails while any scoped block exists, because the old unique index on `ip` alone cannot hold two rows for one address. Delete the scoped blocks first. That is deliberate — dropping them quietly to make the rollback succeed would remove blocks without telling anyone.

**2. ⚠️ Auto-block now defaults to `warn`, and nothing will tell you.** Since **v0.4.0**, a rule with no explicit `mode` reports the address and lets the request through instead of blocking it. If you were relying on auto-block to actually block, set it as part of the upgrade:

```env
WATCHTOWER_AUTO_BLOCK_MODE=block
```

Nothing changes for anyone who already set a mode explicitly, per rule or globally. The reasoning: a rule is written from a guess about traffic nobody has looked at yet, and the cost of guessing wrong is locking real users out — so a new rule reports before it acts. That is the right default for a fresh install and a surprise for an existing one, which is why it is here.

**3. Attack-tool User-Agent rejection is on by default.** Also since **v0.4.0**: a request whose `User-Agent` names sqlmap, Nikto, WPScan, masscan or zgrab is rejected. If you run any of those against your own site from CI or a pentest box, add its address to `WATCHTOWER_NEVER_BLOCK_IPS` or its `User-Agent` to `user_agents.allow` before upgrading — or set `WATCHTOWER_USER_AGENT_FILTER=false`. It rejects the request only and never blocks the address.

**4. ⚠️ `GET /api/blocks` is paginated, so `data` is no longer the whole list.** Since **v0.6.0**, it returns one page (25 rows by default) inside Laravel's paginator body rather than every active block in one array. A script that read `data` as the complete blocklist now silently sees only the first page. Read `total` and follow `next_page_url`, or raise `?per_page=` up to 100. The default filter is still `state=active`, so the first page holds the rows it always did — see [Listing Blocks](#listing-blocks). Nothing else changed shape: `POST /api/block`, `DELETE /api/block/{ip}` and `GET /api/status/{ip}` are untouched.

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
WATCHTOWER_SYNC_QUEUE=          # queue the push-to-master job runs on;
                                # falls back to WATCHTOWER_NOTIFICATION_QUEUE, then 'default'

# Auto-block engine (disabled by default)
WATCHTOWER_AUTO_BLOCK_ENABLED=false
WATCHTOWER_AUTO_BLOCK_MODE=warn    # warn (default) | block | disabled
WATCHTOWER_AUTO_BLOCK_DURATION=60
WATCHTOWER_SHARED_IP_USER_THRESHOLD=3   # distinct signed-in users before a block downgrades to a warning; 0 disables
WATCHTOWER_NEVER_AUTO_BLOCK_IPS=        # automation skips these; an admin can still block them by hand

# Real-time detectors (all disabled by default; no LogScope needed)
WATCHTOWER_DETECT_FAILED_LOGINS=false     # Auth\Events\Failed      — start at 10 in 5 min
WATCHTOWER_DETECT_LOGIN_LOCKOUTS=false    # Auth\Events\Lockout     — start at 3 in 15 min
WATCHTOWER_DETECT_SCANNER_PATHS=false     # /.env, /.git/*, …       — start at 1 in 5 min
WATCHTOWER_DETECT_RESPONSE_BURSTS=false   # 404/429 bursts          — start at 40 in 1 min
WATCHTOWER_DETECT_BAD_USER_AGENT=false    # rejected User-Agents    — start at 5 in 10 min

# Reject requests whose User-Agent names a known attack tool (ON by default)
WATCHTOWER_USER_AGENT_FILTER=true
WATCHTOWER_VERIFY_SEARCH_BOTS=false       # forward-confirmed reverse DNS for Googlebot/Bingbot claims
                                          # ⚠️ blocking DNS on the request path — see the section below

# Webhook notification on every block (optional — useful for n8n, Slack, WhatsApp)
WATCHTOWER_WEBHOOK_URL=
WATCHTOWER_NOTIFICATION_QUEUE=default   # a worker must consume this queue, or the
                                        # webhook is queued where nothing sends it

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

### Listing Blocks

`GET /api/blocks` returns one page of blocks, newest first, with the same `source` and `state` filters the [management page](#%EF%B8%8F-management-page) offers — they share one implementation, so the two lists can't answer the same question differently.

```
GET /watchtower/api/blocks?state=all&source=auto&per_page=50&page=2
```

| Parameter  | Values                              | Default  |
| ---------- | ----------------------------------- | -------- |
| `source`   | `manual`, `auto`, `sync`            | every source |
| `state`    | `active`, `expired`, `all`          | `active` |
| `per_page` | 1–100                               | 25       |
| `page`     | any page number                     | 1        |

The body is Laravel's standard paginator shape — the rows under `data`, the counts and page URLs beside it:

```json
{
  "current_page": 2,
  "data": [{ "id": "01J...", "ip": "203.0.113.50", "source": "auto", "expires_at": null }],
  "per_page": 50,
  "total": 87,
  "last_page": 2,
  "next_page_url": null,
  "prev_page_url": "https://example.com/watchtower/api/blocks?state=all&source=auto&per_page=50&page=1"
}
```

- **An unrecognised filter is ignored, not refused.** `?state=nonsense` lists active blocks rather than returning a 422 — a hand-edited query string shouldn't be an error page on the tool you reach for when something is wrong.
- **`per_page` is capped at 100.** Paginating is the point; without a ceiling, `?per_page=100000` is the unbounded query this endpoint used to be.
- **Page URLs keep your filters**, so paging through a filtered list doesn't silently widen it.
- **Expired blocks exist only until `watchtower:cleanup` next runs.** `?state=expired` can only show what's still there — "it expired an hour ago" and "it was never blocked" look identical once the row is gone.

**Authenticating a non-browser client isn't solved yet.** The management routes carry `watchtower.routes.middleware` (default `['web']`) and the `viewWatchtower` Gate, which is session-cookie authentication — fine for a browser, not for a mobile or CLI client. Token auth is deliberately not built: it needs decisions (which user a token resolves to, what `blocked_by` records for one, whether a token may create blocks or only read them) that shouldn't be guessed at without a real client to answer them. If you have one, say so on [#64](https://github.com/AhmedMerza/laravel-watchtower/issues/64). Until then, a script authenticates however the rest of your app does.

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

## 🖥️ Management Page

A page at your route prefix — `/watchtower` by default — lists what is blocked and lets you block and unblock by hand.

- **The blocklist**, newest first: address or range, scope, source (`manual`, `auto` or `sync`) and the environment it came from, reason, who blocked it, when it was blocked and when it expires. 25 to a page.
- **Filters** by source and by active / expired / all. They live in the query string, so a filtered list is a link you can send someone — and expired blocks are worth looking at, because `watchtower:cleanup` eventually deletes those rows and "it expired an hour ago" then becomes indistinguishable from "it was never blocked".
- **A block form**: an IP or a CIDR range, a reason, and 1 hour / 24 hours / 7 days / permanent. Where you have declared [scopes](#-scoped-blocks), it can block an address from those routes only. Blocking a range wider than IPv4 `/16` or IPv6 `/32` needs the checkbox, the same guard `POST /api/block` applies.
- **Unblock, which asks first.** It lifts exactly the row you clicked: an address with both an app-wide block and a scoped one is two rows, and lifting one leaves the other. (`DELETE /api/block/{ip}` still lifts every scope, because "unblock this address" has to keep meaning the address can use the app again.)
- When LogScope is installed, a block made from a log entry links back to that entry.

It is behind **the same authorization as the API** — the `viewWatchtower` Gate in a standalone install, LogScope's own check when LogScope is present — and there is no setting that exposes the page without the API or the other way round.

The page mounts in **both** modes. LogScope's panel acts on one address at a time from a log entry and has no list of what is currently blocked, so an install with LogScope needs it just as much; there it sits at `/logscope/watchtower`.

**No build step, and nothing loaded from the network.** It is server-rendered Blade with one inline stylesheet and no JavaScript at all — no npm, no CDN, no published assets to keep in step with an upgrade, and it works on a host with no outbound access. The unblock confirmation is a round trip rather than a dialog, so the page needs no `script-src` exception; a strict CSP does need `style-src 'unsafe-inline'` for the stylesheet. It follows the operating system's light or dark setting.

Keep the JSON API and drop the page with:

```env
WATCHTOWER_UI_ENABLED=false
```

To restyle it, publish the views and edit them:

```bash
php artisan vendor:publish --tag=watchtower-views
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

Both directions apply the same two rules, from one implementation:

- **A synced block never downgrades a local one.** An address already blocked
  here by hand or by a rule keeps that block; the incoming record is counted
  as skipped and dropped. It is also what stops a master whose own
  `WATCHTOWER_MASTER_URL` points at itself from rewriting its own blocks.
- **`never_block` wins, wherever the block came from.** An address this
  environment whitelists is never written, whether a satellite pushed it here
  or this satellite pulled it from the master — `watchtower:sync` reports
  those as `refused by never_block`. `never_auto_block` is a different case
  and does *not* survive sync — see the caveat under [Auto-Block](#-auto-block).

---

## 🕵️ Attack-Tool User-Agents

**On by default.** A request whose `User-Agent` names a known attack tool is answered with your [block response](#block-response) instead of being served. Five tools ship on the deny list — every one announces itself in its stock `User-Agent` and none has legitimate production traffic:

| Tool | What it is | Stock `User-Agent` |
|---|---|---|
| **sqlmap** | Automated SQL-injection finder and exploiter | `sqlmap/1.8.2#stable (https://sqlmap.org)` |
| **Nikto** | Web server vulnerability scanner | `Mozilla/5.00 (Nikto/2.5.0) (Evasions:None)…` |
| **WPScan** | WordPress user, plugin and version enumeration | `WPScan v3.8.22 (https://wpscan.com/…)` |
| **masscan** | Internet-wide port scanner, on its HTTP banner grab | `masscan/1.3 (https://github.com/…/masscan)` |
| **zgrab** | The HTTP side of ZMap, used for internet-wide surveys | contains `zgrab` |

> ⚠️ **This is not a security boundary and cannot be one.** The client writes its own `User-Agent`, and every tool above changes it with a single flag — `sqlmap --random-agent`, `nikto -useragent`, `wpscan --user-agent`. What it removes is the background noise of unattended scanners running defaults, which is most of what actually reaches a production app, for the cost of one regex match with no cache read and no DB read. Someone deliberately after *you* walks straight past it.

Because it is spoofable, **a match rejects the request and never blocks the address.** That is the headline safety property, and it holds until you arm the [`bad_user_agent` detector](#detectors) deliberately.

### What it deliberately does not reject

`curl`, `python-requests`, `Go-http-client`, `okhttp` — and **an empty `User-Agent`**. Real API clients, webhooks, mobile apps and uptime monitors all send those, and the big community "bad bot" lists that include them are why people switch this kind of filtering back off. Keep anything you add to the deny list equally unambiguous: a pattern that overlaps a real client 403s the people using it.

### Running these tools against your own site

Three ways past the filter, in the order they are checked:

1. **`never_block`** — those addresses and ranges skip the check entirely. Your pentest source range or CI egress IP belongs here.
2. **`user_agents.allow`** — checked before `deny`, so it wins. Name your own scanner rather than dropping a pattern everyone else benefits from:
   ```bash
   sqlmap --user-agent="sqlmap acme-security-audit" -u https://example.com
   ```
   ```php
   'allow' => ['acme-security-audit'],
   ```
3. **Remove the entry from `user_agents.deny`** — it is a plain config array.

To turn the whole thing off, `WATCHTOWER_USER_AGENT_FILTER=false`. That is read at boot, so the middleware is not in the stack at all — but it also means toggling it needs a worker restart under Octane. The lists themselves are live.

### Patterns

Plain **case-insensitive substrings**, not regexes — a `.` is a literal dot. They are compiled into one expression and reused, so matching is a single regex call per request however long the list grows, and a malformed entry cannot break the expression or the request.

Rejections are logged at **debug** level on `log_channel`. A single scan is thousands of requests and this has no throttle, so production levels drop them; turn the channel up while you are tuning patterns.

### Escalating to a real block

`bad_user_agent` is an ordinary [detector](#detectors), off by default, that counts requests the filter already rejected:

```env
WATCHTOWER_AUTO_BLOCK_ENABLED=true
WATCHTOWER_DETECT_BAD_USER_AGENT=true
```

It starts at **5 in 10 minutes** rather than the `1` [`scanner_paths`](#detectors) uses. Both read a client-controlled part of the request, but a path like `/.env` is one a real client never asks for by accident, while a `User-Agent` is a single header anyone can set to anything — including on someone else's behalf where proxy trust is loose. A real scan reaches 5 within seconds; one crafted header does not. Once armed it goes through the same `AutoBlockService::record()` every other detector uses, so `warn` mode, `never_block`, `never_auto_block` and the [shared-IP guard](#shared-ips) all apply.

### Verifying search bots

Off by default. With `WATCHTOWER_VERIFY_SEARCH_BOTS=true`, a request claiming to be Googlebot or Bingbot is checked with **forward-confirmed reverse DNS**: its PTR record must sit under one of the bot's domains *and* resolve back to the same address. The forward half is the half that matters — whoever controls an address controls its PTR and can point it at `googlebot.com`; only Google can make `googlebot.com` resolve back to them. A verified crawler skips the deny list; one that fails is something pretending to be Google.

> ⚠️ **These are blocking resolver calls on the request path, and PHP gives them no timeout.** How long they take is the OS resolver's `timeout`/`attempts` to decide — tens of seconds against a black-holed nameserver. They also fail by *returning false* rather than throwing, so no `try`/`catch` bounds them, and anyone can trigger the path by sending `User-Agent: Googlebot`. That is why it is off by default, and why it wants a local caching resolver in front of it.

Three things keep it from being a way to tie up your worker pool:

- **Both outcomes are cached**, not just the successes — otherwise anyone spoofing Googlebot gets a free resolver lookup on every request of a scan. A confirmed verdict lasts `cache_hours` (default 24).
- **The key is the network a block would cover** (`{cache.key}:ua:bot:{bot}:{target}`), not the bare address. Keyed per address, one attacker-owned IPv6 /64 would be billions of distinct cache misses, each a fresh lookup and a fresh cache entry.
- **`max_lookups_per_minute` (default 30) caps lookups across the whole app.** Over budget, the claim is trusted and nothing is written, so it gets verified properly once there is budget again. `0` removes the cap.

A successful verification costs *two* lookups — the PTR, then the forward confirmation — so read the cache as "one verification per address per TTL", not one round-trip.

**What a resolver outage costs you:** a lookup that cannot answer is not the same as a claim that checks out, so real crawlers are rejected while it lasts. `gethostbyaddr()` returns the address unchanged both when there is genuinely no PTR record and when the resolver simply failed, and the two are indistinguishable — so that verdict is cached for **5 minutes**, not `cache_hours`, and a momentary blip costs a crawler minutes rather than a day. A *definitive* no — a PTR that exists and doesn't match, or doesn't resolve back — is cached for the full TTL. A cache outage is the one case that does fail open: without somewhere to record the verdict there is no way to bound the lookups, so the claim is trusted and the degradation is logged.

---

## 🤖 Auto-Block

Two ways to block automatically, sharing one set of guards:

- **Detectors** react to Laravel's own signals — a failed login, a login lockout, a probe for `/.env`, a burst of 404s, a scanner naming itself in its `User-Agent` — as they happen. No log table, **no LogScope**, and the block lands within the same request instead of on the next scheduled run.
- **Log rules** match patterns in LogScope's log table (`logscope.table`, default `log_entries`), evaluated every minute by the scheduler. These need LogScope installed.

Everything here is off unless you turn it on: auto-block itself is disabled, **every detector is disabled**, and `rules` ships empty.

> ⚠️ **Tune carefully or lock real users out.** An overly broad rule or detector can block legitimate traffic across every environment. **Both are a dry run by default** — they report what they would have caught and block nobody until you arm them.

```env
WATCHTOWER_AUTO_BLOCK_ENABLED=true
WATCHTOWER_AUTO_BLOCK_MODE=warn    # warn (default) | block | disabled
WATCHTOWER_AUTO_BLOCK_DURATION=60  # minutes
WATCHTOWER_SHARED_IP_USER_THRESHOLD=3
WATCHTOWER_ESCALATION=false              # longer blocks for repeat offenders
WATCHTOWER_ESCALATION_DECAY_DAYS=30
WATCHTOWER_NEVER_AUTO_BLOCK_IPS=203.0.113.0/24

# Detectors — all off by default, turn on one at a time
WATCHTOWER_DETECT_FAILED_LOGINS=false
WATCHTOWER_DETECT_LOGIN_LOCKOUTS=false
WATCHTOWER_DETECT_SCANNER_PATHS=false
WATCHTOWER_DETECT_RESPONSE_BURSTS=false
WATCHTOWER_DETECT_BAD_USER_AGENT=false
```

**Modes** (global default, overridable per rule *and* per detector):

| Mode | Behaviour |
|------|-----------|
| `warn` | **The default.** Match the rule and emit a structured `would_have_blocked: true` log entry on the configured log channel — but **do not** block. Tail your logs for that key to see what the rule would catch, then set `WATCHTOWER_AUTO_BLOCK_MODE=block` to arm it. |
| `block` | Actually block matching IPs. |
| `disabled` | Skip the rule entirely. A per-rule kill switch without deleting the definition. |

### Detectors

Each one counts per IP in the cache and blocks through the same path a rule does, so `never_block`, `never_auto_block` and the shared-IP guard all still apply. A request that matches nothing costs nothing — the middleware isn't even added to the stack unless a detector that reads the request is enabled.

| Detector | Signal | Default | Start at |
|---|---|---|---|
| `failed_logins` | `Illuminate\Auth\Events\Failed`, fired by every guard on a bad credential | off | 10 in 5 min |
| `login_lockouts` | `Illuminate\Auth\Events\Lockout`, fired by the Breeze / Fortify / `ThrottlesLogins` login throttle | off | 3 in 15 min |
| `scanner_paths` | A request for a configured path pattern | off | 1 in 5 min |
| `response_bursts` | Responses with a configured status (`404`, `429`) | off | 40 in 1 min |
| `bad_user_agent` | A request the [User-Agent filter](#%EF%B8%8F-attack-tool-user-agents) already rejected | off | 5 in 10 min |

```php
'auto_block' => [
    'detectors' => [
        'failed_logins'  => ['enabled' => true, 'count' => 10, 'window_minutes' => 5],
        'login_lockouts' => ['enabled' => true, 'count' => 3,  'window_minutes' => 15],

        'scanner_paths' => [
            'enabled'        => true,
            'count'          => 1,
            'window_minutes' => 5,
            'patterns'       => ['/.env', '/.git/*', '/wp-login.php', '/xmlrpc.php', '/phpmyadmin*'],
        ],

        // Armed only after watching it in warn mode for a full traffic cycle
        'response_bursts' => [
            'enabled'        => true,
            'count'          => 40,
            'window_minutes' => 1,
            'statuses'       => [404, 429],
            'mode'           => 'warn',
        ],

        // Escalates the User-Agent filter from rejecting each request to
        // blocking the address behind them
        'bad_user_agent' => ['enabled' => true, 'count' => 5, 'window_minutes' => 10],
    ],
],
```

A few things worth knowing before you arm any of these:

- **`scanner_paths` answers the matching request itself.** A probe for `/.env` gets the block response rather than your 404, so a pattern that overlaps a real route never serves it even once. That cuts both ways: **a pattern that overlaps a route your users need will lock them out of it**, so keep the list to paths nothing legitimate asks for. Matching runs against the *decoded* path, so `/%2Eenv` is caught too. The threshold of `1` is deliberate — a single request for `/.env` is not a mistake.
- **`response_bursts` is the loosest and most likely to catch a real person.** It reads the status after the response is sent, so it costs the request nothing, but a broken deploy that 404s its own assets looks exactly like enumeration. Leave it in `warn` mode for a full traffic cycle and raise the count to whatever your own logs say is normal.
- **`bad_user_agent` only sees what the filter already rejected**, so it does nothing unless `user_agents` is on, and a `never_block` address never reaches it. Its threshold is `5` rather than `scanner_paths`' `1` because a `User-Agent` is one header anyone can set to anything — see [Attack-Tool User-Agents](#%EF%B8%8F-attack-tool-user-agents).
- **`login_lockouts` builds on a limit you already set.** It counts the throttle your login form already applies, so one lockout is someone fumbling a password and several is someone working through a list.
- **The counter resets on every decision**, so a block that lapses doesn't re-fire on the next signal.
- **A detector that decides to block and is held back from doing it reports once, not once per request.** A real block takes the address away from the detector entirely — a blocked scanner never reaches the counter again — and nothing did that for a decision that was only *reported*: `warn` mode, or a `never_auto_block` refusal. So the address kept arriving and kept being re-decided, which at `scanner_paths`' `count` of `1` meant a log line for every probe. The decision is now held for `block_duration_minutes` — the same span the block would have covered — and the detector ignores the address until it lapses, so a `warn`-mode log reads as one entry per block it predicts rather than one per request. **Arming a detector still takes effect on the very next request** rather than waiting the hold out, because the hold records the mode it was opened under. Taking an address *off* `never_block` or `never_auto_block` takes effect on its next signal, too: the hold records which guard held the decision back, and a `never_*` refusal — which names one address, while the hold covers the prefix a block would have — is re-checked against the list for the address now asking, so one exempt entry can't shield the rest of its `/64`. The entry still carries the `hits` that crossed the threshold, but that is a count of what it took to decide, not of everything the address sent — for that, read the traffic where it lands, in your web server log or LogScope.
- **A [shared-IP](#shared-ips) hold is the exception: it is re-measured, never held.** `warn` mode and `never_auto_block` are settings that will say the same thing in an hour; how many signed-in users an address is showing is not. Holding that answer would turn a guard an attacker has to keep re-earning into an hour of immunity bought once — so a shared address is re-counted on every crossing, and blocks on the first one where the accounts have stopped appearing.
- **`scanner_paths` at `count: 1` means one request is enough to block.** Every other path to a block needs accumulation. That is deliberate for paths nothing legitimate requests, but it also means a **misconfigured trusted proxy** — one that forwards a client-supplied `X-Forwarded-For` verbatim — lets an attacker name an innocent address and get it blocked with a single crafted request. Watchtower warns when `TrustProxies` is missing entirely, but it cannot detect an overly-permissive one. Get proxy trust right before arming this.
- **Toggling a detector's `enabled` flag takes effect at boot, not live.** Its `count`, `window_minutes`, `mode` and `patterns` are re-read on every signal, but whether a detector is wired up at all is decided when the provider boots. Under Octane, Swoole, RoadRunner or a long-lived queue worker, switching one on or off needs a worker restart.

### Shared IPs

Plenty of real users share one public address: mobile carriers put subscribers behind carrier-grade NAT, and offices, universities and VPN exits do the same. Count errors per IP and a rule tuned to catch **one** bad actor ends up blocking **everyone** behind that gateway.

So before it blocks, watchtower counts how many **distinct signed-in users** the log saw from that address during the window. At or above `WATCHTOWER_SHARED_IP_USER_THRESHOLD` (default `3`) the block downgrades to a warning carrying `not_blocked_because: shared IP`. Set the threshold to `0` to switch the guard off.

The count covers **all** of the address's logged traffic, not just the rows the rule matched — the question is how many people a block would hit, not how many of them tripped it. An address where one buggy client throws every error while two hundred others browse fine is the case this exists for.

**Detectors have no log table to ask**, so they count the signed-in users seen on the requests they themselves counted, and the `would_have_blocked` entry carries the actual `user_ids` alongside `distinct_users` — deciding whether to arm a detector is much easier when you can see *who* was behind a flagged address rather than just how many. Nothing is recorded for traffic that matches no detector.

**The same caveat applies, and more sharply.** The guard counts signed-in users and can't tell real ones from accounts an attacker made — and for detectors the identity comes from the *matching* requests themselves, so an attacker doesn't even need separate innocent traffic: signing in as three throwaway accounts while probing is enough to downgrade `response_bursts` to warn-only for their address. Read the guard as protection against **your own detector misfiring on a real shared gateway** — a broken deploy 404ing assets for three signed-in staff, which it handles exactly right — and never as a control an adversary respects. For that, use `never_block`, or keep `scanner_paths` at its default `count` of `1`, which fires before any accumulation is possible.

That makes the guard strongest for `response_bursts`, where the requests are often signed in, and **blind for `failed_logins` and `login_lockouts`**, where by definition nobody is. It would be easy to count the account the credentials were *aimed* at instead — and wrong: an attacker working through a list of usernames would report a new distinct "user" on every attempt, read as a busy office, and stand the guard down. The guard would be disarmed by exactly the attack it is in the way of. So those two detectors report no users at all, and **`never_auto_block` is the protection for a known office or carrier range** before you arm them.

Limits worth knowing:

- **It can be gamed wherever anyone can sign up.** The guard counts signed-in users; it cannot tell real ones from accounts an attacker made. Where registration is open, someone who authenticates three throwaway accounts from their own address — one harmless request each is enough — downgrades every auto-block against that address to a warning, and the attack traffic itself needn't be signed in at all. Raise `WATCHTOWER_SHARED_IP_USER_THRESHOLD` above what an attacker will bother creating, and treat the guard as protection against *your own rules misfiring*, not as a control an adversary respects. When you need a decision automation can't be argued out of, that's `never_block`.
- It only sees users your app actually logged. It protects an address your users are signed in from; it can't recognise a busy gateway whose traffic is all anonymous.
- Anonymous traffic counts for nobody, so a scanner hitting you while signed out still gets blocked. That is deliberate.

For gateways the guard can't see, list them explicitly:

```env
WATCHTOWER_NEVER_AUTO_BLOCK_IPS=203.0.113.0/24,2001:db8:2::/48
```

`never_auto_block` binds automation only — **an admin can still block a listed address by hand**, through the UI or the API. That is the whole difference from `never_block`, which nothing can override. Use `never_auto_block` for "a rule would be right about this traffic and wrong about the people behind it", and `never_block` for "never, under any circumstances".

**It survives sync in both directions.** The sync payload carries what decided
each block, so a receiving node applies its own `never_auto_block` to a block
another environment's *rule* made, while still accepting one an admin there
made by hand — which is the distinction the list exists for. `never_block` is
enforced on every synced block regardless, as it always was.

> ⚠️ **One node at a time, during an upgrade.** A satellite running a version
> older than 0.6.0 doesn't send that field, and a node that can't tell what
> decided a block treats it as unknown rather than as automation — so an old
> satellite keeps syncing exactly as it does today, and its admins' manual
> blocks keep working. `never_auto_block` starts covering that satellite's
> automated blocks once it is upgraded. `watchtower:sync` counts what it turns
> away as `refused by never_auto_block`, separately from `never_block`.

### Escalating durations

An hour is a pause, not a deterrent, for someone who comes back. Turn this on and an address that earns a **second** auto-block gets a longer one, and a third longer again.

```env
WATCHTOWER_ESCALATION=true
WATCHTOWER_ESCALATION_DECAY_DAYS=30
```

```php
'escalation' => [
    'enabled'          => env('WATCHTOWER_ESCALATION', false),
    'repeat_durations' => [360, 1440, 10080],   // minutes
    'decay_days'       => env('WATCHTOWER_ESCALATION_DECAY_DAYS', 30),
],
```

The **first** auto-block always lasts `block_duration_minutes`. `repeat_durations` is the 2nd, 3rd, 4th… and its last value repeats from then on, so the defaults above read: **1 hour → 6 hours → 1 day → 1 week** for every offence after that. Keeping the first block out of the list is what stops two settings claiming the same number — switching escalation on can lengthen a block, never shorten one.

**The count decays.** An address that goes quiet for `decay_days` starts again at the bottom, so an address reassigned to somebody else isn't serving the last tenant's sentence. `watchtower:cleanup` forgets those ledgers on its next run.

**What doesn't escalate:**

| | Why |
|---|---|
| A `warn`-mode near miss | A dry run has to stay one. Arming a rule later would otherwise hand out six-hour blocks on the strength of blocks that never happened. |
| An address held back for being shared | It wasn't blocked, so it didn't offend. A shared address downgraded to a **scoped** block *was* blocked, and does count. |
| Manual blocks, and blocks arriving over sync | Both carry the duration their caller asked for. Only the auto-block engine consults the ladder. |

The count lives in the `ip_offences` table, one row per address per scope, so it survives `cache:clear` — and each scope keeps its own ladder. Two offences on your login routes don't decide how long an app-wide block lasts.

> Counts are **per environment**. Sync carries blocks, not ledgers, so a satellite that has seen one offence won't inherit the master's count. That is deliberate: the offence happened where it happened.

### Log rules

These read LogScope's log table, so they need LogScope installed — and they only see what your app actually logged, which is why Laravel's own 404s are invisible to them and `scanner_paths` exists. Define them in `config/watchtower.php`:

```php
'auto_block' => [
    'enabled'                  => env('WATCHTOWER_AUTO_BLOCK_ENABLED', false),
    'mode'                     => env('WATCHTOWER_AUTO_BLOCK_MODE', 'warn'),
    'shared_ip_user_threshold' => env('WATCHTOWER_SHARED_IP_USER_THRESHOLD', 3),
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

Rules run every minute via the scheduler — detectors don't need it, since they act inside the request. Add the scheduler to your server if not already running:

```bash
* * * * * cd /your-app && php artisan schedule:run >> /dev/null 2>&1
```

> **Note:** IPs in `WATCHTOWER_NEVER_BLOCK_IPS` are never auto-blocked, even if they match a rule. Those in `WATCHTOWER_NEVER_AUTO_BLOCK_IPS` are skipped by automation but remain blockable by hand.

---

## 🎯 Scoped Blocks

A block normally covers the whole app. A **scoped** block covers only the routes you tag with it.

This is the middle option between blocking everyone behind a shared address and blocking nobody. Mobile carriers put thousands of subscribers behind one address, and offices and VPN exits do the same — so the [shared-IP guard](#shared-ips) downgrades a block on one to a warning, which also leaves the attacker among them free to carry on. A scoped block takes away the routes the evidence points at and leaves everyone else the rest of the app.

It takes **two changes, and neither does anything alone.**

**1. Declare the scope** in `config/watchtower.php`:

```php
'scopes' => ['auth'],
```

**2. Put the middleware on the routes it should cover.** Watchtower can't do this for you — only your app knows where its login routes are:

```php
// Laravel Breeze
Route::middleware('watchtower:auth')->group(function () {
    Route::post('/login', [AuthenticatedSessionController::class, 'store']);
    Route::post('/forgot-password', [PasswordResetLinkController::class, 'store']);
    Route::post('/reset-password', [NewPasswordController::class, 'store']);
});

// Laravel Fortify — wrap its routes, or set Fortify's own middleware config
Route::middleware('watchtower:auth')->group(function () {
    require base_path('vendor/laravel/fortify/routes/routes.php');
});
```

One route can name more than one scope: `watchtower:auth,admin` blocks an address blocked in either.

Then scope a block, by hand:

```bash
curl -X POST https://your-app.test/watchtower/api/block \
  -d 'ip=203.0.113.9' -d 'scope=auth'
```

…or from a rule or detector:

```php
'failed_logins' => [
    'enabled'        => true,
    'count'          => 10,
    'window_minutes' => 5,
    'scope'          => 'auth',
],
```

### What changes when a rule has a scope

A shared address that trips a **scoped** rule gets a scoped block instead of only a warning:

| | shared address trips the rule | one user trips it |
|---|---|---|
| no scope | warning only, attacker continues | blocked app-wide |
| `scope: auth` | **blocked on auth routes only** | blocked on auth routes only |

`warn` mode still only warns — a dry run stays a dry run whatever its scope — and `never_block` and `never_auto_block` are unchanged.

### Things worth knowing

- **Scopes default to off.** Every rule and detector ships with `'scope' => null`, meaning app-wide, exactly as before. Nothing changes for an existing install until you opt in.
- **A scope no route carries enforces nothing.** `php artisan watchtower:install` lists each declared scope and whether any route names it, and warns about the mirror mistake — a route naming a scope the config doesn't declare. A scope name that isn't declared is refused outright — a typo blocks nothing loudly rather than silently.
- **A scoped block is only ever enforced by the route middleware.** Nothing in the global stack acts on one, including the `scanner_paths` detector, which answers a probe itself when it blocks app-wide but not when it blocks in a scope.
- **Scoped blocks don't sync.** They stay on the node that made them: the sync payload has no scope field, and your satellites have their own route files. Tracked in [#37](https://github.com/AhmedMerza/laravel-watchtower/issues/37).
- **`GET /api/status/{ip}`** keeps `blocked` meaning *blocked app-wide*. Scoped blocks appear under a separate `scopes` key, so nothing reads a scoped block as a full one.
- **`DELETE /api/block/{ip}`** lifts every scope. Add `?scope=auth` to lift just one.
- **Cost:** a route without the middleware reads exactly the cache keys it always did. A scoped route reads two more, for that scope only.

---

## 🔧 Artisan Commands

```bash
# First-time setup (publish config + run migration)
php artisan watchtower:install

# Pull blacklist from master and rebuild the local cache
php artisan watchtower:sync

# Delete expired temporary blocks and rebuild the cache
# Also forgets offence ledgers that have decayed (see Escalating durations)
# Runs automatically every day — set WATCHTOWER_CLEANUP_ENABLED=false to manage manually
# Permanent blocks (no expiry) are never touched
php artisan watchtower:cleanup

# Backtest the auto-block rules against the log history you already have.
# Read-only — it writes nothing, whatever mode the rules are in.
php artisan watchtower:simulate --days=7
php artisan watchtower:simulate --rule=0 --json
```

### Backtesting a rule before you arm it

`warn` mode is the honest way to try a rule out, and it costs days: set it,
wait, read logs. `watchtower:simulate` skips the waiting, because LogScope
already kept the history the rule would have read:

```
Rule #0 — level=error, 10 hit(s) in 5 min [block]
  1 address(es) would have been blocked, 1 block(s) in total.
+--------------+--------+------------------+------------------+-------+-----------------+-----------+
| IP           | Blocks | First            | Last             | Users | Clean signed-in | Guard     |
+--------------+--------+------------------+------------------+-------+-----------------+-----------+
| 198.51.100.4 | 1      | 2026-09-21 10:30 | 2026-09-21 10:30 | 4     | 4               | held back |
+--------------+--------+------------------+------------------+-------+-----------------+-----------+
  1 of these also sent signed-in traffic that never matched the rule — a block would have taken that away too.
  1 would have been held back by the shared-IP guard (>= 3 signed-in users), so they would have been warnings, not blocks.
```

The two warning lines are the point. **Clean signed-in** counts requests from
that address that carried a signed-in user and never matched the rule — people
who were doing nothing wrong and would have lost access anyway. **Guard** says
whether the shared-IP guard would have stepped in, computed against the window
the live guard would actually have read at that moment, not the whole period.

It needs LogScope's log table and reports on whatever history is there, so a
fresh install has nothing to say until logs accumulate. It reports every
configured rule regardless of `auto_block.enabled` or a rule's `mode` — the
reason you are running it is to decide those.

It knows what the engine knows. A rule whose `scope` isn't declared in
`watchtower.scopes` is skipped by the engine, so it is reported as skipped
rather than simulated. Addresses covered by `never_block` or
`never_auto_block` are listed separately instead of counted as would-be
blocks, because the engine refuses those whatever a rule says. And on a
*scoped* rule the shared-IP guard doesn't hold a block back — it narrows it
to that scope — so the report says "scoped", not "warning".

**Two deliberate inexactnesses, both erring towards over-reporting.** The
engine evaluates rules on a one-minute scheduler tick; the replay walks the
rows and notices a crossing at the row that caused it, up to a minute
earlier. And escalating durations are not modelled — every simulated block
lasts `block_duration_minutes`, so an address that would have earned a
longer second block shows slightly more blocks here than it got. Rules are
also replayed independently, while the live engine skips an address another
rule has already blocked, so two overlapping rules can both claim the same
address.

### Cost, honestly

Memory is bounded: each address is replayed through a ring buffer holding at
most `count` timestamps, so one that logged a million rows costs the same as
one that logged fifty.

Query cost is a different matter, and worth knowing before you point this at
a large table. The narrowing pass admits any address with `count` matching
rows *anywhere in the period* — a much weaker filter than "`count` inside one
window" — so on busy traffic it admits many addresses that never actually
trip the rule, and each one is then streamed individually. LogScope has no
`(ip_address, occurred_at)` index, so those per-address reads have no ideal
plan.

If you run this regularly against a large `log_entries`, add the composite
index:

```php
Schema::table('log_entries', fn (Blueprint $t) => $t->index(['ip_address', 'occurred_at']));
```

It is a write cost on LogScope's hottest table, so measure before you keep
it. Start with a small `--days` and widen.

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
