# Cross-Environment Sync

[← Back to the README](../README.md) · [All docs](README.md)

Block an address in one environment and every other environment picks it up within minutes.

Watchtower supports a **master/satellite** topology. One environment (production) is the master. Others (staging, alpha) pull from it.

## Setup

**On every environment** (master + satellites), add to `.env`:

```env
WATCHTOWER_MASTER_URL=https://your-production-app.com
WATCHTOWER_SYNC_SECRET=same-secret-on-all-environments
```

and say which end each one is:

```env
WATCHTOWER_SYNC_ROLE=master      # on the master
WATCHTOWER_SYNC_ROLE=satellite   # on every other environment
```

That's the whole setup — there are no routes to hand-write. The master
registers the two the sync protocol uses, `GET /watchtower/sync/blocks` and
`POST /watchtower/sync/block`, and authenticates them with the shared secret.
Satellites hold the same secret to sign their requests, but serve neither
route.

The paths are fixed, not affected by `WATCHTOWER_ROUTE_PREFIX`: the satellite
signs the path it calls, so both ends have to agree on it. They're also outside
the `web` middleware group — no session, no CSRF — because they're
machine-to-machine.

> ⚠️ **The secret is a credential, and it is fleet-wide.** Anyone holding it can
> block any IP on every environment at once, and read the master's blocklist.
> Use a long random value, keep it out of version control, and rotate it on all
> environments together.

**What the role changes:**

| `WATCHTOWER_SYNC_ROLE` | Serves the sync routes | Pushes its blocks to the master | `watchtower:sync` |
|---|---|---|---|
| `master` | yes | no — it is the master | refuses: schedule it on satellites |
| `satellite` | no | yes | pulls |
| unset | yes | yes | pulls |

Unset is how every environment behaved before the role existed, and it still
works, but each satellite then serves the sync endpoints as well. An
unrecognised value counts as `satellite`, so a typo exposes less rather than
more, and `watchtower:sync` reports it. If a satellite's `watchtower:sync` or
push gets **HTTP 404**, the master isn't serving the routes: check that the
master has the secret set and its role is `master`, not `satellite`.

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

## How Push + Pull Work Together

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
  and does *not* survive sync — see the caveat under [Auto-Block](auto-block.md).

## Repairing Drift

`php artisan watchtower:reconcile` re-pushes every active global block to the
master — the push-side complement to `watchtower:sync`'s pull. Nothing
automatically retries a push whose queued job exhausted its 3 tries; this is
how you catch those up without waiting for the next time each address is
blocked again. Not scheduled by default — add it to the satellite's schedule
on whatever cadence suits you. See [Artisan Commands](commands.md).

The same command repairs every other enabled [block target](block-targets.md)
the same way — a satellite running the Cloudflare or nginx_file target in
particular relies on it, since a block learned only through this page's pull
never reaches either target live.
