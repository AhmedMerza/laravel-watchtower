# Security Notes

[← Back to the README](../README.md) · [All docs](README.md)

How Watchtower behaves at the edges: behind proxies, during a cache outage, and on the wire between environments.

**Trusted proxies:** Watchtower checks `$request->ip()` in a global middleware registered directly after Laravel's `TrustProxies`, so the forwarded client IP has already been resolved. It still runs before sessions, auth and routing. If your app is behind a load balancer or proxy, configure trusted proxies (`$middleware->trustProxies(at: ...)` in `bootstrap/app.php`), otherwise every request looks like it comes from the proxy. If you've removed `TrustProxies` from the global stack, Watchtower runs first and sees the direct peer address.

**Cache outages fail open:** if the cache store throws during the lookup, the request is let through unchecked rather than returning a 500. The failure is logged on `watchtower.log_channel` roughly once a minute, and the cache warm-up stands down for the same window, so an outage can't fill the disk with one log line per request. The throttle window is kept in marker files under `storage/framework/`; on a read-only filesystem it degrades to per-process throttling. The check isn't atomic, so requests already in flight when an outage starts can each log once before the window closes — expect a small burst at onset, then one line per minute.

**HMAC signatures:** Sync requests are signed by the satellite and verified by the master. The signature is `hash_hmac('sha256', timestamp + METHOD + path + rawBody, WATCHTOWER_SYNC_SECRET)`, sent as `X-Watchtower-Signature` alongside `X-Watchtower-Timestamp`; `Watchtower\Support\SyncSignature` is the one implementation both ends use. The master compares with `hash_equals` and rejects anything unsigned, wrongly signed, or carrying a timestamp more than `sync.timestamp_tolerance` seconds (default 300) from its own clock, which bounds how long a captured request stays replayable. Method and path are inside the signed string, so a captured read can't be replayed as a write. Use a long, random secret and keep it identical across environments.

**Cache TTL:** Each per-IP cache entry carries a 24-hour TTL (configurable via `cache.ttl_hours`) as a safety net. The cache is explicitly rebuilt on every block/unblock and on `watchtower:sync`; if the store is flushed or its entries expire, the next lookup warms it from the DB.

## What Watchtower doesn't do, and why

Watchtower decides which addresses to turn away, and turns them away. Other firewall packages do more, and these are the gaps people look for first. Each answer says what to use instead.

**Account bans.** Watchtower blocks addresses, not users. Banning an account is a different product, with its own model and its own UI. Use [mchev/banhammer](https://github.com/mchev/banhammer), which bans models (users, teams) as well as IPs.

**Country blocking.** If you're behind Cloudflare, use a WAF custom rule on `ip.src.country`: it's free, it runs before the request reaches your server, and Cloudflare keeps its own GeoIP data current. Without Cloudflare, an optional GeoIP lookup is tracked in [#126](https://github.com/AhmedMerza/laravel-watchtower/issues/126). Don't call a lookup API on every request, as some firewall packages do: it adds a network round trip to every request and fails when the API does.

**Request-input inspection (SQL injection, XSS, file inclusion).** Not built. Regex checks on input catch some scanners, but they also catch real users, such as a comment that says "select the one from the list", and blocking on them turns a false positive into a lockout. A warn-first detector, which reports what it would have blocked before you arm it, is tracked in [#125](https://github.com/AhmedMerza/laravel-watchtower/issues/125). Meanwhile, Laravel already closes the holes those regexes guard: the query builder and Eloquent bind parameters, so input never becomes SQL; Blade's `{{ }}` escapes output; `VerifyCsrfToken` rejects forged form posts; and validation rejects input that doesn't fit. A scanner probing for those holes usually also trips [`scanner_paths`](auto-block.md#detectors) or [`response_bursts`](auto-block.md#detectors).

**Rate limiting.** Use Laravel's own: the `throttle` middleware and `RateLimiter::for()`. A rate limit slows a client down and lets it back in; a Watchtower block turns it away. `response_bursts` doesn't count 429s by default for that reason: a client your limiter is already handling isn't evidence of an attack.

Coming from another package? See [Migrating from akaunting/laravel-firewall](migrating-from-akaunting.md) or [Migrating from antonioribeiro/firewall](migrating-from-firewall.md).
