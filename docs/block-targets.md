# Block Targets

[← Back to the README](../README.md) · [All docs](README.md)

A global block normally only enforces here: this node's own cache and database. A **block
target** pushes it somewhere else too, so an attacker is turned away before a request ever
boots Laravel. [Cross-Environment Sync](sync.md) is the first one ("another Laravel
environment"); this page covers the next: **Cloudflare**. An `nginx_file` target (atomic deny-file
writes) is tracked in [#25](https://github.com/AhmedMerza/laravel-watchtower/issues/25).

Every enabled target is pushed to by the same queued listener on every block/unblock, and
repaired by the same `php artisan watchtower:reconcile` — see
[Cross-Environment Sync § Repairing Drift](sync.md#repairing-drift).

## Cloudflare

Pushes a block as an account-level **IP Access Rule** (not an IP List — Access Rules are
simpler and available on every plan tier including Free, and this package has no need for an
IP List's much larger, Enterprise-gated capacity). Rules apply **account-wide**, across every
zone — an attacker IP is blocked everywhere you run Cloudflare, which is the whole point.

### Setup

```env
WATCHTOWER_CLOUDFLARE_ENABLED=true
WATCHTOWER_CLOUDFLARE_ACCOUNT_ID=your-cloudflare-account-id
WATCHTOWER_CLOUDFLARE_API_TOKEN=your-api-token
```

Create the token as a **Custom Token** scoped to **Account → Firewall Access Rules → Edit**
for the account above. It needs no zone-level permissions.

### What it does, and doesn't, touch

Every rule this target creates is tagged with a fixed note. `watchtower:reconcile` and a later
unblock only ever act on rules carrying that tag — **a rule you added by hand in the Cloudflare
dashboard is never read, changed, or deleted by Watchtower.**

If a rule for the same address already exists and isn't tagged as Watchtower's (one you added
yourself, in any mode), the block fails loudly — logged on `watchtower.log_channel` — rather
than silently overwriting it. Cloudflare allows only one rule per address regardless of mode or
notes, so this can't be worked around; remove or rename the conflicting rule first.

### CIDR ranges

A scoped IPv6 block (the `ipv6_block_prefix` setting, default `/64` — see
[Configuration](configuration.md)) and an admin-submitted CIDR both push as a *range* rather
than a single address. Cloudflare's IP Access Rules only accept specific prefix lengths for a
range:

| Family | Accepted prefixes |
|---|---|
| IPv4 | `/16`, `/24` |
| IPv6 | `/32`, `/48`, `/64` |

The default IPv6 prefix (`/64`) fits. A narrower admin-forced range (`force=true` on the block
API) or an IPv4 CIDR outside `/16`/`/24` does not — that block still applies locally and on
every other target, but is skipped on Cloudflare with a logged reason instead of pushed.

### Rate limits

Cloudflare's account-wide API limit is 1,200 requests per 5 minutes — generous for the two
calls (a lookup, then a create/delete) a live block or unblock makes. `watchtower:reconcile`
can make many more on a large
blocklist; see [#108](https://github.com/AhmedMerza/laravel-watchtower/issues/108) for the
general `watchtower:reconcile` scaling work that applies here too.
