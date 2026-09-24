# Attack-Tool User-Agents

[← Back to the README](../README.md) · [All docs](README.md)

Rejects requests from well-known attack tools that name themselves in their `User-Agent`. On by default. It rejects the request only, and never blocks the address.

**On by default.** A request whose `User-Agent` names a known attack tool is answered with your [block response](configuration.md#block-response) instead of being served. Five tools ship on the deny list — every one announces itself in its stock `User-Agent` and none has legitimate production traffic:

| Tool | What it is | Stock `User-Agent` |
|---|---|---|
| **sqlmap** | Automated SQL-injection finder and exploiter | `sqlmap/1.8.2#stable (https://sqlmap.org)` |
| **Nikto** | Web server vulnerability scanner | `Mozilla/5.00 (Nikto/2.5.0) (Evasions:None)…` |
| **WPScan** | WordPress user, plugin and version enumeration | `WPScan v3.8.22 (https://wpscan.com/…)` |
| **masscan** | Internet-wide port scanner, on its HTTP banner grab | `masscan/1.3 (https://github.com/…/masscan)` |
| **zgrab** | The HTTP side of ZMap, used for internet-wide surveys | contains `zgrab` |

> ⚠️ **This is not a security boundary and cannot be one.** The client writes its own `User-Agent`, and every tool above changes it with a single flag — `sqlmap --random-agent`, `nikto -useragent`, `wpscan --user-agent`. What it removes is the background noise of unattended scanners running defaults, which is most of what actually reaches a production app, for the cost of one regex match with no cache read and no DB read. Someone deliberately after *you* walks straight past it.

Because it is spoofable, **a match rejects the request and never blocks the address.** That is the headline safety property, and it holds until you arm the [`bad_user_agent` detector](auto-block.md#detectors) deliberately.

## What it deliberately does not reject

`curl`, `python-requests`, `Go-http-client`, `okhttp` — and **an empty `User-Agent`**. Real API clients, webhooks, mobile apps and uptime monitors all send those, and the big community "bad bot" lists that include them are why people switch this kind of filtering back off. Keep anything you add to the deny list equally unambiguous: a pattern that overlaps a real client 403s the people using it.

## Running these tools against your own site

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

## Patterns

Plain **case-insensitive substrings**, not regexes — a `.` is a literal dot. They are compiled into one expression and reused, so matching is a single regex call per request however long the list grows, and a malformed entry cannot break the expression or the request.

Rejections are logged at **debug** level on `log_channel`. A single scan is thousands of requests and this has no throttle, so production levels drop them; turn the channel up while you are tuning patterns.

## Escalating to a real block

`bad_user_agent` is an ordinary [detector](auto-block.md#detectors), off by default, that counts requests the filter already rejected:

```env
WATCHTOWER_AUTO_BLOCK_ENABLED=true
WATCHTOWER_DETECT_BAD_USER_AGENT=true
```

It starts at **5 in 10 minutes** rather than the `1` [`scanner_paths`](auto-block.md#detectors) uses. Both read a client-controlled part of the request, but a path like `/.env` is one a real client never asks for by accident, while a `User-Agent` is a single header anyone can set to anything — including on someone else's behalf where proxy trust is loose. A real scan reaches 5 within seconds; one crafted header does not. Once armed it goes through the same `AutoBlockService::record()` every other detector uses, so `warn` mode, `never_block`, `never_auto_block` and the [shared-IP guard](auto-block.md#shared-ips) all apply.

## Verifying search bots

Off by default. With `WATCHTOWER_VERIFY_SEARCH_BOTS=true`, a request claiming to be Googlebot or Bingbot is checked with **forward-confirmed reverse DNS**: its PTR record must sit under one of the bot's domains *and* resolve back to the same address. The forward half is the half that matters — whoever controls an address controls its PTR and can point it at `googlebot.com`; only Google can make `googlebot.com` resolve back to them. A verified crawler skips the deny list; one that fails is something pretending to be Google.

> ⚠️ **These are blocking resolver calls on the request path, and PHP gives them no timeout.** How long they take is the OS resolver's `timeout`/`attempts` to decide — tens of seconds against a black-holed nameserver. They also fail by *returning false* rather than throwing, so no `try`/`catch` bounds them, and anyone can trigger the path by sending `User-Agent: Googlebot`. That is why it is off by default, and why it wants a local caching resolver in front of it.

Three things keep it from being a way to tie up your worker pool:

- **Both outcomes are cached**, not just the successes — otherwise anyone spoofing Googlebot gets a free resolver lookup on every request of a scan. A confirmed verdict lasts `cache_hours` (default 24).
- **The key is the network a block would cover** (`{cache.key}:ua:bot:{bot}:{target}`), not the bare address. Keyed per address, one attacker-owned IPv6 /64 would be billions of distinct cache misses, each a fresh lookup and a fresh cache entry.
- **`max_lookups_per_minute` (default 30) caps lookups across the whole app.** Over budget, the claim is trusted and nothing is written, so it gets verified properly once there is budget again. `0` removes the cap.

A successful verification costs *two* lookups — the PTR, then the forward confirmation — so read the cache as "one verification per address per TTL", not one round-trip.

**What a resolver outage costs you:** a lookup that cannot answer is not the same as a claim that checks out, so real crawlers are rejected while it lasts. `gethostbyaddr()` returns the address unchanged both when there is genuinely no PTR record and when the resolver simply failed, and the two are indistinguishable — so that verdict is cached for **5 minutes**, not `cache_hours`, and a momentary blip costs a crawler minutes rather than a day. A *definitive* no — a PTR that exists and doesn't match, or doesn't resolve back — is cached for the full TTL. A cache outage is the one case that does fail open: without somewhere to record the verdict there is no way to bound the lookups, so the claim is trusted and the degradation is logged.
