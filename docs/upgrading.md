# Upgrading

[← Back to the README](../README.md) · [All docs](README.md)

What to check when you upgrade an existing install. The [CHANGELOG](../CHANGELOG.md) has the full detail for every release.

**1. Run the migrations.** Recent releases added the `scope` column on `blacklisted_ips`, the `ip_offences` table that escalating durations use, the `hits` columns, and the `feed` block source:

```bash
# re-publish so the new ones land — this is the only way they run (#104)
php artisan vendor:publish --tag=watchtower-migrations

php artisan migrate
```

**Installed before 0.7.0 and never published the migrations?** Then they ran straight from vendor, and your `migrations` table lists them without a date (`create_blacklisted_ips_table`, …). Upgrade to **0.10.1 or later** before publishing. From 0.10.1, the published copy of each of those migrations sees the undated record and does nothing, going up or down, so publishing and migrating only adds what you're missing (#128). On an older release the published copies try to create the tables again and fail.

⚠️ Rolling the `scope` migration *back* fails while any scoped block exists, because the old unique index on `ip` alone cannot hold two rows for one address. Delete the scoped blocks first. That is deliberate — dropping them quietly to make the rollback succeed would remove blocks without telling anyone.

**2. ⚠️ Auto-block now defaults to `warn`, and nothing will tell you.** Since **v0.4.0**, a rule with no explicit `mode` reports the address and lets the request through instead of blocking it. If you were relying on auto-block to actually block, set it as part of the upgrade:

```env
WATCHTOWER_AUTO_BLOCK_MODE=block
```

Nothing changes for anyone who already set a mode explicitly, per rule or globally. The reasoning: a rule is written from a guess about traffic nobody has looked at yet, and the cost of guessing wrong is locking real users out — so a new rule reports before it acts. That is the right default for a fresh install and a surprise for an existing one, which is why it is here.

**3. Attack-tool User-Agent rejection is on by default.** Also since **v0.4.0**: a request whose `User-Agent` names sqlmap, Nikto, WPScan, masscan or zgrab is rejected. If you run any of those against your own site from CI or a pentest box, add its address to `WATCHTOWER_NEVER_BLOCK_IPS` or its `User-Agent` to `user_agents.allow` before upgrading — or set `WATCHTOWER_USER_AGENT_FILTER=false`. It rejects the request only and never blocks the address.

**4. ⚠️ `GET /api/blocks` is paginated, so `data` is no longer the whole list.** Since **v0.6.0**, it returns one page (25 rows by default) inside Laravel's paginator body rather than every active block in one array. A script that read `data` as the complete blocklist now silently sees only the first page. Read `total` and follow `next_page_url`, or raise `?per_page=` up to 100. The default filter is still `state=active`, so the first page holds the rows it always did — see [Listing Blocks](api.md#listing-blocks). Nothing else changed shape: `POST /api/block`, `DELETE /api/block/{ip}` and `GET /api/status/{ip}` are untouched.

**5. ⚠️ A published config keeps the old `response_bursts` defaults.** Since **v0.11.0** (#121), `response_bursts` stops counting 429 and ships with its own `shared_ip_user_threshold` of `1`: one signed-in user holds an app-wide block back. Laravel merges a package's config only one level deep, so if you published `config/watchtower.php`, your `detectors` block keeps the old values. Bring them across by hand:

```php
'response_bursts' => [
    // ...
    'statuses'                 => [404],
    'shared_ip_user_threshold' => 1,
],
```

Keep `429` only if `count` sits above your rate limiter's limit; otherwise the limiter itself trips the block. See [Auto-Block](auto-block.md).
