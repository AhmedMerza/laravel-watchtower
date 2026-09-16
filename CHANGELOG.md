# Changelog

All notable changes to `laravel-watchtower` will be documented in this file.

## [Unreleased]

### Security

- **Sync requests were signed but nothing verified the signature.** Satellites computed an HMAC and sent it; the package shipped no verification code and no master-side routes. The README instead asked adopters to hand-write two unauthenticated closures at `/watchtower/api/blacklist` and `/watchtower/api/block`, so anyone who could reach the master could block any IP — and have it propagate to every satellite on the next sync — or read the full blocklist. The `POST /watchtower/api/block` in that snippet also collided with the package's own management route, making a push 419 on CSRF depending on registration order. Watchtower now ships the master side: `GET /watchtower/sync/blocks` and `POST /watchtower/sync/block`, registered automatically when `WATCHTOWER_SYNC_SECRET` is set, outside the `web` group, behind a new `VerifySyncSignature` middleware that recomputes the signature with `hash_equals` and rejects timestamps outside a configurable window. ([#12](https://github.com/AhmedMerza/laravel-watchtower/issues/12))

### Changed

- **BREAKING (sync wire protocol): the sync paths moved to `/watchtower/sync/blocks` and `/watchtower/sync/block`,** off the management API and away from `WATCHTOWER_ROUTE_PREFIX` — the satellite signs the path it calls, so it can't depend on the master's prefix config. Master and satellites must be upgraded together. The signed string is unchanged in shape (`timestamp + METHOD + path + rawBody`) and now has a single implementation, `Watchtower\Support\SyncSignature`, used by both the clients and the middleware.
- **`PushBlockToMaster` no longer re-pushes a block that arrived by sync,** and the master ignores an incoming push for an IP already blocked locally by hand or by auto-block. Without both, a master whose own `WATCHTOWER_MASTER_URL` points at itself — the documented setup — would push every incoming block straight back to itself in a loop.
- **`watchtower:sync` now fails with a clear message when `WATCHTOWER_SYNC_SECRET` is unset,** and `PushBlockToMaster` logs a warning instead of sending a request the master will reject.

### Added

- **`watchtower.sync.timestamp_tolerance`** (`WATCHTOWER_SYNC_TOLERANCE`, default 300 seconds) — how far a signed request's timestamp may sit from the master's clock. Bounds the window in which a captured request can be replayed.

### Documentation

- The sync section now says that the routes come up on **any** environment with a secret, satellites included, since registration is gated on the secret alone and satellites need it to sign ([#36](https://github.com/AhmedMerza/laravel-watchtower/issues/36) tracks separating the two capabilities). It also warns to keep satellite egress IPs in `WATCHTOWER_NEVER_BLOCK_IPS` on the master: the blocking middleware is global, so a blocked satellite stops syncing in both directions and `watchtower:sync` reports only `HTTP 403`.

### Fixed

- **The one-click Block IP button in LogScope's detail panel now works.** It built its API base by rewriting LogScope's — `/logscope/api` → `/logscope/guard/api` — a path left over from the `logscope-guard` → `watchtower` rename. The routes are mounted at `/logscope/watchtower/api`, so the status check, block and unblock calls all 404'd; the button looked functional until you clicked it. The API routes are now named (`watchtower.api.block`, `.unblock`, `.status`, `.blocks`) and the partial renders its URLs from those names, so a prefix change can't make them drift apart again. The partial also renders nothing, instead of throwing, when `WATCHTOWER_ROUTES_ENABLED=false`. ([#11](https://github.com/AhmedMerza/laravel-watchtower/issues/11))
- **The documented minimum LogScope version was wrong, and the Block IP button never rendered below it.** `composer.json`'s `suggest` and README both said `>=1.5.2`, but LogScope only began including this package's `watchtower::partials.ip-actions` in **1.6.1** — 1.5.2 through 1.6.0 include the pre-rename `logscope-guard::` partial, a namespace this package hasn't registered since the rename. Anyone on those versions got no button at all. Both now say `>=1.6.1`, and the `prefer-lowest` CI job tests against a version where the integration actually exists.
- **Blocks were ignored behind a load balancer or reverse proxy.** The blocking middleware was prepended to the global stack, ahead of `TrustProxies`, so `$request->ip()` returned the proxy's address and never matched a blocked client IP. It is now inserted directly after `TrustProxies` (or an app subclass of it), still ahead of sessions, auth and routing. If `TrustProxies` isn't in the global stack, it still goes first. ([#14](https://github.com/AhmedMerza/laravel-watchtower/issues/14))
- **A cache outage no longer makes every request return 500.** If the blocklist lookup throws (Redis down, a mistyped `WATCHTOWER_CACHE_STORE`), the request is let through unchecked and the failure is logged at `error` on `watchtower.log_channel`, at most once a minute across all workers. ([#13](https://github.com/AhmedMerza/laravel-watchtower/issues/13))
- **A cache or DB outage no longer floods the log from the boot-time cache warm-up.** `warmOnBoot()` runs on every request, and each failure wrote its own `warning` — so an outage produced a log line per request regardless of the throttle above. A failed warm-up now stands down for a minute, which also drops the repeated doomed round-trip to the dead backend. The throttle is not atomic: requests already in flight at the onset of an outage can each log once before the window closes. ([#13](https://github.com/AhmedMerza/laravel-watchtower/issues/13))
- **An empty blocklist no longer costs a DB query on every request.** `rebuild()` forgot the index key when no IPs were blocked, but `warmOnBoot()` reads a missing index as "needs warming" — so a site with an empty blocklist (the default state of a fresh install, or any site whose blocks have all expired) re-ran `BlacklistedIp::active()->get()` on every single request, forever. `rebuild()` now writes an empty index instead.
- **Watchtower now warns when `TrustProxies` isn't in the global middleware stack.** In that case blocking runs first and sees the direct peer address, which behind a proxy is the proxy's IP — the same silent failure as [#14](https://github.com/AhmedMerza/laravel-watchtower/issues/14). It was detected and discarded; it's now logged (throttled) on `watchtower.log_channel`.
- **Registering the middleware is idempotent again.** The move from `prependMiddleware()` to `array_splice()` dropped the "skip if already present" guard Laravel's helper has, so a repeated registration would have run the whole blocklist check twice per request.

### Changed

- **BREAKING (subclassers only): `BlacklistCache::rebuild()` returns `bool` instead of `void`.** It reports whether the DB read succeeded, so `warmOnBoot()` can stand down when it didn't. PHP does not permit a `void` override of a `bool` method, so any subclass overriding `rebuild(): void` must update its signature. Callers that ignore the return value are unaffected.
- **Minimum Laravel version raised to 11.0** (`illuminate/* >=11.0`). The service provider uses the `Illuminate\Support\Facades\Schedule` facade, which only exists from Laravel 11 — the previous `>=10.0` constraint never actually worked on Laravel 10. Laravel 10 is also past its security-support window. Surfaced by a new `prefer-lowest` CI job.

### Added

- **Cache abstraction — Redis is no longer a hard dependency.** `BlacklistCache` now uses `Cache::store(config('watchtower.cache.store'))` instead of direct Redis facade calls. Any cache driver Laravel supports works: redis, memcached, file, database, array, dynamodb. New env var `WATCHTOWER_CACHE_STORE` (default falls back to your app's `cache.default`). Internally the cache uses per-IP keys (`{prefix}:ip:{ip}`) plus a sidecar index (`{prefix}:_index`) so `rebuild()` can clear stale entries on any driver — no `Cache::tags()` requirement (file/database stores don't support tagging). `composer.json` `require` swaps `illuminate/redis` → `illuminate/cache`. The legacy `watchtower.cache.connection` config key is deprecated but still in the config schema (ignored by the new code); users wanting a non-default Redis connection should now configure a custom cache store in `config/cache.php` and point `WATCHTOWER_CACHE_STORE` at it. Performance: request-time is unchanged (one cache `get`); rebuilds do N+1 writes vs. the previous single HMSET, but rebuilds are rare (only on block/unblock/sync).
- **Auto-block warn-only mode** — new `watchtower.auto_block.mode` config (`block` | `warn` | `disabled`, default `block`) plus optional per-rule `mode` override. In `warn` mode, the engine matches rules and emits a structured `would_have_blocked: true` log entry on the configured `log_channel`, but does NOT actually block — operators can validate a rule against real traffic before flipping it to `block`. `disabled` skips a rule entirely (per-rule kill switch). New env var: `WATCHTOWER_AUTO_BLOCK_MODE`. Backward-compatible: configs that don't set a mode get the prior `block` behaviour.

### Changed (BREAKING — single rename release)

- **Package renamed: `ahmedmerza/logscope-guard` → `ahmedmerza/watchtower`.** Reflects the strategic pivot away from "LogScope addon" toward "standalone Laravel app-edge blocker, with optional LogScope integration."
- **Namespace renamed: `LogScopeGuard\` → `Watchtower\`.** All `use LogScopeGuard\…` imports must be updated.
- **Service provider renamed: `LogScopeGuardServiceProvider` → `WatchtowerServiceProvider`.**
- **Config file renamed: `config/logscope-guard.php` → `config/watchtower.php`.** Re-run `php artisan vendor:publish --tag="watchtower-config" --force` if you've published a customized version.
- **All env vars renamed: `GUARD_*` → `WATCHTOWER_*`.** Backward-compat aliases are in place for one transition release — `WATCHTOWER_*` takes precedence, but if unset, the old `GUARD_*` values are still consulted. Scheduled to be removed in v1.1.
- **All artisan commands renamed: `guard:install` → `watchtower:install`, `guard:sync` → `watchtower:sync`, `guard:cleanup` → `watchtower:cleanup`.**
- **Cache key renamed: `logscope_guard:blacklist` → `watchtower:blacklist`.** On first boot under the new name, the old Redis key is ignored and a fresh hash is rebuilt from the DB. No data loss; just a brief warm-up window.
- **HTTP routes moved: `/logscope/guard/*` → `/logscope/watchtower/*` (LogScope mode) or `/watchtower/*` (standalone mode).** Update any external callers.
- **Sync wire protocol updated: HMAC signature path `POST/guard/api/block` → `POST/watchtower/api/block` (and the GET equivalent for sync).** Headers renamed: `X-Guard-Signature` → `X-Watchtower-Signature`, `X-Guard-Timestamp` → `X-Watchtower-Timestamp`. **Both master and satellites must be on the same version** — mixing pre/post-rename versions across envs will fail signature verification.

### Added

- **Standalone routing config block (`watchtower.routes.*`).** Previously the package only knew how to mount routes under LogScope's prefix — when LogScope was absent, it still read `config('logscope.routes.prefix', 'guard')` (a leak from a foreign config namespace, working only by virtue of the default). The standalone branch now reads `watchtower.routes.prefix` (default `'watchtower'`), `watchtower.routes.domain`, and `watchtower.routes.middleware` from the package's own config. New `WATCHTOWER_ROUTES_ENABLED` env flag lets users disable the management routes entirely.
- **`watchtower:install` detects LogScope and prints branch-specific next-steps.** Standalone users get a prominent warning that the management routes have no built-in auth until v1.1.

### Notes for migration

- The transitional meta-package `ahmedmerza/logscope-guard` will be published as a thin wrapper that just `require`s `ahmedmerza/watchtower` for one release, then deprecated. Existing users can upgrade in two steps if needed: first to the meta-package release, then to the new name directly.


