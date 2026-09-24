# Upgrading

[← Back to the README](../README.md) · [All docs](README.md)

What to check when you upgrade an existing install. The [CHANGELOG](../CHANGELOG.md) has the full detail for every release.

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

**4. ⚠️ `GET /api/blocks` is paginated, so `data` is no longer the whole list.** Since **v0.6.0**, it returns one page (25 rows by default) inside Laravel's paginator body rather than every active block in one array. A script that read `data` as the complete blocklist now silently sees only the first page. Read `total` and follow `next_page_url`, or raise `?per_page=` up to 100. The default filter is still `state=active`, so the first page holds the rows it always did — see [Listing Blocks](api.md#listing-blocks). Nothing else changed shape: `POST /api/block`, `DELETE /api/block/{ip}` and `GET /api/status/{ip}` are untouched.
