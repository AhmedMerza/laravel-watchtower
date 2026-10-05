# Migrating from akaunting/laravel-firewall

[← Back to the README](../README.md) · [All docs](README.md)

[akaunting/laravel-firewall](https://github.com/akaunting/laravel-firewall) is a set of route middleware that inspect each request and answer a match with a 403. Watchtower is one global middleware that turns away blocked addresses, plus detectors that decide which addresses to block. This page maps one to the other.

## Why there's no importer

There's nothing worth importing:

- **`firewall_ips` holds only its own auto-blocks.** It has no static blacklist and no manual block API. Every row comes from its `auto_block` listener, and each expires `period` seconds later, which is 30 minutes for every rule in the shipped config. By the time you've installed Watchtower, the rows are gone or about to be.
- **`firewall_logs` is attack history, not a list of decisions.** Keep the table if you want the history; Watchtower doesn't read it.

What carries over is your allowlist and your intent. The rest of this page covers both.

## The allowlist

`FIREWALL_WHITELIST` becomes `WATCHTOWER_NEVER_BLOCK_IPS`, with the same format: a comma-separated list of IPs and CIDR ranges, IPv4 or IPv6.

```dotenv
# Before
FIREWALL_WHITELIST=203.0.113.10,10.0.0.0/8

# After
WATCHTOWER_NEVER_BLOCK_IPS=127.0.0.1,::1,203.0.113.10,10.0.0.0/8
```

- **Keep `127.0.0.1,::1`.** They're Watchtower's default, and setting the variable replaces the default.
- **List IPv6 networks, not addresses.** Watchtower blocks a whole IPv6 `/64` from one address, but a `never_block` entry protects only what it says. To keep an IPv6 network reachable, list its range. See [IP Ranges and IPv6](configuration.md#ip-ranges-and-ipv6).
- **It's at least as strong as akaunting's.** A listed address is never blocked by any means (the management page, the API, auto-block, sync or a feed), and the [User-Agent filter](user-agents.md) never rejects it either.

Watchtower also has a softer list akaunting doesn't: `WATCHTOWER_NEVER_AUTO_BLOCK_IPS`, for addresses that rules should leave alone but an admin can still block by hand, such as an office gateway or a mobile carrier's NAT. See [Configuration](configuration.md).

## The middleware

Remove `firewall.*` from your routes; Watchtower needs no route middleware for app-wide blocks. Then, for each one you used:

| akaunting middleware | What it did | In Watchtower |
|---|---|---|
| `firewall.ip` | 403 for an address in `firewall_ips` | Built in. Every blocked address is turned away by the global middleware, from cache |
| `firewall.whitelist` | 403 for every address **not** on the whitelist, on the routes carrying it | Not built. Protect an admin area with your own middleware or your server config. Watchtower's [management page and API](management-page.md) sit behind the `viewWatchtower` Gate |
| `firewall.agent` | Rejected empty or malicious User-Agents, and browsers, platforms or devices you listed | Partly: the [User-Agent filter](user-agents.md) rejects attack tools (sqlmap, Nikto and others), and the `bad_user_agent` detector turns repeat offenders into blocks. An empty User-Agent is [deliberately let through](user-agents.md#what-it-deliberately-does-not-reject), since real API clients and monitors send one. There are no browser, platform or device lists |
| `firewall.bot` | Allowed or blocked named crawlers | Not built as a crawler list. The User-Agent filter can [verify search bots](user-agents.md#verifying-search-bots), so a client claiming to be Googlebot has to be Googlebot |
| `firewall.geo` | Allowed or blocked by country, calling a lookup API on every request | Not built. See [What Watchtower doesn't do](security.md#what-watchtower-doesnt-do-and-why) |
| `firewall.url` | 403 for listed paths | The `scanner_paths` [detector](auto-block.md#detectors) answers probes for `/.env`, `/.git*`, `/wp-login.php` and similar, and blocks the address. Add your own patterns, but only for paths nothing legitimate requests: one request blocks |
| `firewall.referrer` | 403 for listed `Referer` values | Not built |
| `firewall.lfi`, `.rfi`, `.php`, `.session`, `.sqli`, `.xss` | Regex checks on request input | Not built. See [What Watchtower doesn't do](security.md#what-watchtower-doesnt-do-and-why) |
| `firewall.swear` | Rejected input containing listed words | Not built, and not planned: it's content moderation, not security |
| `firewall.all` | All of the above as one group | Not needed: Watchtower is already global |
| Failed-login listener | Counted failed logins toward an auto-block | The `failed_logins` and `login_lockouts` [detectors](auto-block.md#detectors) |

**akaunting blocked on the first match; Watchtower's detectors start in warn mode.** A detector you enable logs what it would have blocked until you arm it, and you can [backtest a rule](auto-block.md#backtesting-a-rule-before-you-arm-it) against last week's logs first. Blocks also last longer: 60 minutes by default rather than 30. Set `WATCHTOWER_ESCALATION=true` and an address that comes back gets longer blocks each time ([escalation](auto-block.md#escalating-durations), off by default).

**Notifications:** akaunting could mail or post to Slack on every detected attack. Watchtower posts each block to a [webhook](configuration.md#webhook-notification), which can feed Slack or n8n. Mail and Slack through Laravel Notifications are tracked in [#124](https://github.com/AhmedMerza/laravel-watchtower/issues/124).

## Behind Cloudflare

**akaunting trusts the `CF-Connecting-IP` header from anyone.** If the header is present, it uses it as the client address, with no check that the request came through Cloudflare:

```php
if ($cf_ip = $this->request->header('CF_CONNECTING_IP')) {
```

A client that reaches your origin directly can send any address in that header. It can get past the whitelist that way, or get someone else's address blocked.

**Watchtower reads `$request->ip()`, after Laravel's `TrustProxies`.** It sees the forwarded address only when the request came from a proxy you trust. Behind Cloudflare, trust Cloudflare's published ranges ([cloudflare.com/ips](https://www.cloudflare.com/ips/)) in `bootstrap/app.php`:

```php
->withMiddleware(function (Middleware $middleware) {
    $middleware->trustProxies(at: [
        // Cloudflare's IPv4 and IPv6 ranges, from cloudflare.com/ips
    ]);
})
```

Without this, every request looks like it comes from Cloudflare, and one auto-block would take out all your traffic. See [Security Notes](security.md). To turn blocked addresses away at Cloudflare's edge, before they reach Laravel at all, use the [Cloudflare block target](block-targets.md).

## Removing the old package

1. Remove every `firewall.*` middleware from your routes and the `firewall.all` group.
2. `composer remove akaunting/laravel-firewall`, and delete `config/firewall.php` and the `FIREWALL_*` variables.
3. Drop `firewall_ips` and `firewall_logs` when you no longer want the history. Watchtower uses neither.
