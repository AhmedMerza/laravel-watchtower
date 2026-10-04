# Public Blocklist Feeds

[← Back to the README](../README.md) · [All docs](README.md)

`watchtower:import-feeds` imports public lists of known-bad networks as blocks, so that traffic is turned away before it ever reaches your app. It runs daily on Laravel's scheduler. Every feed is off until you turn it on.

```env
WATCHTOWER_FEED_SPAMHAUS_DROP=true
# or
WATCHTOWER_FEED_FIREHOL_LEVEL1=true
```

| Feed | What it lists | Size |
|---|---|---|
| `spamhaus_drop` | Spamhaus DROP: hijacked netblocks and ones run by criminals. High confidence. Free to use under [their terms](https://www.spamhaus.org/drop/terms/). | ~1,800 ranges, IPv4 and IPv6 |
| `firehol_level1` | [FireHOL level1](https://iplists.firehol.org/?ipset=firehol_level1): a broader list, and it **already includes most of DROP**, so most apps need one or the other, not both. | ~4,600 ranges |

To run an import now instead of waiting for the schedule:

```bash
php artisan watchtower:import-feeds
```

## What an import does

- **It replaces the previous import.** A range a feed stops listing is unblocked on the next run. When several feeds are on, a range stays blocked as long as *any* of them lists it.
- **It never touches your own blocks.** Manual, auto and sync blocks are left exactly as they are. An address you already block keeps your block, with your reason.
- **It never imports private or reserved ranges.** FireHOL level1 lists the bogons, which include `10.0.0.0/8`, `172.16.0.0/12` and `192.168.0.0/16`. Importing those as-is would block your own load balancer, health checks and queue workers, so any range that overlaps an IANA special-purpose range is dropped. So is any entry wider than an IPv4 `/10` or an IPv6 `/24` (the real feeds' widest are a `/12` and a `/29`).
- **A feed that covers implausibly much is refused whole.** The real feeds cover at most 0.42% of IPv4. A feed covering more than ~3% of IPv4 (2^27 addresses), or more than 2^44 IPv6 `/64`s, is treated like a bad download: a broken or compromised list could otherwise block a large part of the internet one valid-looking entry at a time.
- **Feeds are only read over HTTPS**, and a redirect may not step down to plain HTTP.
- **A bad download removes nothing.** If a feed fails to download, lists nothing usable, or shrinks to less than half the size it listed last time, its existing entries are kept, nothing is removed that run, and the command exits non-zero so the scheduler's failure reporting picks it up. Feeds that did download still have their new entries added.
- **`never_block` still wins** on every request, including over a feed range that covers the address.

## Where feed blocks go

They stay on the environment that imported them. A feed block is **not** synced to other environments, **not** pushed to [block targets](block-targets.md), and doesn't fire the webhook. Every environment runs its own import, and thousands of ranges re-imported daily aren't something to mirror into Cloudflare's rule list.

On the [management page](management-page.md) and in the [API](api.md), feed blocks have the source `feed`, and `blocked_by` names the feed (`feed:spamhaus_drop`).

**Unblocking a feed entry by hand only lasts until the next import.** To keep an address reachable, add it to `WATCHTOWER_NEVER_BLOCK_IPS`.

## Performance

A feed adds thousands of ranges, and each request is checked against all of them. The range list is cached as sorted, packed address ranges and binary-searched. With 5,000 ranges loaded, a lookup takes microseconds rather than the ~6ms a linear scan took, and a test enforces a time budget for it.

## Adding your own feed

Any HTTPS URL that serves one IP or CIDR per line works. Lines starting with `#` or `;` are skipped, and the first address on each line is used, so one-JSON-object-per-line formats work too. Add an entry to `feeds` in `config/watchtower.php`:

```php
'feeds' => [
    // ...
    'my_list' => [
        'enabled' => true,
        'urls'    => ['https://example.com/blocklist.txt'],
    ],
],
```

Turning a feed off removes its entries on the next scheduled run.
