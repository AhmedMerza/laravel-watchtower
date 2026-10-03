# Block Targets

[← Back to the README](../README.md) · [All docs](README.md)

A global block normally only enforces here: this node's own cache and database. A **block
target** pushes it somewhere else too, so an attacker is turned away before a request ever
boots Laravel. [Cross-Environment Sync](sync.md) is the first one ("another Laravel
environment"); this page covers the other two: **Cloudflare** and **nginx_file**.

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

## nginx_file

Writes one `deny {ip};` line per active block to a plain file, atomically, then runs a
configured reload command so nginx picks it up. Unlike Cloudflare, this target owns the whole
file — it's a dedicated `include`, not a namespace an admin also writes to by hand — so there's
no foreign-content or conflict case to detect, and no CIDR prefix restriction: `deny` accepts
any IPv4 or IPv6 address or range as written.

### Setup

```env
WATCHTOWER_NGINX_FILE_ENABLED=true
WATCHTOWER_NGINX_FILE_PATH=/etc/nginx/watchtower-deny.conf
WATCHTOWER_NGINX_FILE_RELOAD_COMMAND="sudo /usr/sbin/nginx -s reload"
```

Add **one line** to whichever `http`, `server`, or `location` block should enforce the list:

```nginx
include /etc/nginx/watchtower-deny.conf;
```

No trailing `allow all;` needed — nginx's access module defaults to **allow** when no `deny`/
`allow` rule matches. If that block already has `allow`/`deny` rules of its own, place the
`include` deliberately relative to them: a context's own `allow`/`deny` rules are **not**
inherited together with a parent's, so where you put this line, and what else shares the
context, decides what actually applies.

**The file must exist before nginx first loads that `include` line**, or `nginx -t` and every
reload after it fail outright. Run `php artisan watchtower:reconcile` once, or `touch` the path
yourself, before adding the `include`.

### Permissions

The directory holding `path` must already exist and be writable by whatever user runs your
queue worker — this package never creates it. nginx's own user only needs read access to the
file. Keep the two apart: don't point `path` at a file something else (a hand-maintained
include, another tool) also writes to — the whole file is overwritten on every change.

### The reload command

`reload_command` is optional. Leave it unset if a systemd path unit (or similar) watches the
file and reloads nginx on its own — this target's job is only to write the file correctly, not
to guarantee something else reloads it. If you do set it, it runs as your queue worker's user,
which normally can't reload nginx directly; grant just that one command, e.g. a sudoers entry:

```
www-data ALL=(root) NOPASSWD: /usr/sbin/nginx -s reload
```

A failing reload command raises an error (caught and logged like any other target failure) with
its exit code and captured stderr.

### Reload cost

Every block and unblock reloads nginx — unless the write turns out to be a no-op (the value was
already in, or already out). nginx's reload is a worker-process restart, not free; on a host
auto-blocking frequently, that's a real cost per block. There's no batching here: each block
reloads once, same as the issue's own proposal asked for. `watchtower:reconcile`'s own write is
also skipped (no rewrite, no reload) when it finds no drift, which is what keeps a scheduled
`watchtower:reconcile` from reloading nginx every time it runs and nothing has moved.
