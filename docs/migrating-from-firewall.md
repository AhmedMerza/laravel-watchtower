# Migrating from antonioribeiro/firewall

[← Back to the README](../README.md) · [All docs](README.md)

[antonioribeiro/firewall](https://github.com/antonioribeiro/firewall) stopped at Laravel 10. Watchtower can import its lists, so you don't have to retype years of blocks.

## 1. Import your lists

Install Watchtower and run its migrations first. You can remove the old package before or after: the importer reads its `firewall` table with the query builder and its `config/firewall.php` as plain config, and needs none of its code.

```bash
# Dry run: lists every entry and what would happen to it. Writes nothing.
php artisan watchtower:import-firewall

# Write the blocks.
php artisan watchtower:import-firewall --commit
```

It reads both places the old package kept entries: the `firewall` table, if it exists, and the `blacklist` / `whitelist` arrays in `config/firewall.php`. Running it again imports nothing twice. If a run fails after writing, for example because the cache was unreachable, run it again: it rebuilds the cache and reconciles without adding anything new.

| Old entry | What the importer does |
|---|---|
| Blacklisted IP or CIDR range | A permanent block, keeping the old row's timestamps, with the reason "Imported from antonioribeiro/firewall" |
| Netmask (`10.0.0.0/255.0.0.0`), wildcard (`172.17.*.*`), dash range (`10.0.0.1-10.0.0.9`) | Converted to the CIDR ranges that cover exactly the same addresses |
| A file path in the config arrays | Read, one entry per line, including files it lists |
| Whitelisted entry | Printed as a `WATCHTOWER_NEVER_BLOCK_IPS` line and a `never_block` array for you to paste. Watchtower reads that list from config, so the importer can't write it |
| `host:` entry | Skipped. A hostname's address can change, so add its current IP by hand |
| `country:` entry | Skipped. Watchtower has no GeoIP; block countries at the edge, e.g. with [Cloudflare](block-targets.md) |
| Anything else | Skipped |

Every skipped entry is listed with its reason. A blacklisted entry is also skipped if:

- **It's also whitelisted.** The old package let it through.
- **`never_block` covers it.**
- **It's wider than a `/16`.** Watchtower makes you confirm those. Block it by hand with `force` if you meant it.
- **It's already blocked permanently.** That block is kept exactly as it is. A temporary block, or a [feed](feeds.md) entry, for the same target is replaced by the permanent one, since it would otherwise lapse and let the address back in.

A whitelisted entry wider than a `/16` isn't suggested for `never_block`. The importer names it instead, because pasting a `/0` there would turn blocking off.

The import doesn't send a webhook or a notification for each block. After writing, it rebuilds the cache once and runs [`watchtower:reconcile`](commands.md) once, so your [block targets](block-targets.md) and, on a satellite, the master get the whole list in one go.

To undo an import, unblock the rows with that reason. Going through `unblockRecord()` updates the cache and tells your block targets, which a plain `delete()` does not:

```php
use Watchtower\Console\Commands\ImportFirewallCommand;
use Watchtower\Models\BlacklistedIp;
use Watchtower\Services\BlacklistService;

BlacklistedIp::where('reason', ImportFirewallCommand::REASON)
    ->each(fn ($row) => app(BlacklistService::class)->unblockRecord($row));
```

## 2. Replace the middleware

| Old | Watchtower |
|---|---|
| `FirewallBlacklist` | Nothing to add. Watchtower's middleware is global |
| `BlockAttacks` | The [auto-block detectors and rules](auto-block.md) |
| `FirewallWhitelist` (only allowlisted IPs get in) | **No equivalent.** Use an `allow` / `deny` rule in your web server, or a short middleware of your own |

## 3. Replace facade and command calls

| Old | Watchtower |
|---|---|
| `Firewall::blacklist($ip)` | `app(BlacklistService::class)->block($ip)` |
| `Firewall::remove($ip)` | `app(BlacklistService::class)->unblock($ip)` |
| `Firewall::isBlacklisted($ip)` | `app(BlacklistService::class)->isBlocked($ip)` |
| `Firewall::find($ip)` | `app(BlacklistService::class)->find($ip)` |
| `Firewall::whitelist($ip)` | Add it to `never_block` in config |
| `firewall:blacklist`, `firewall:remove`, `firewall:list` | The [management page](management-page.md) or the [JSON API](api.md) |
| `firewall:cache:clear` | Not needed: every block and unblock updates the cache |
| `firewall:whitelist` | Add it to `never_block` in config |

`BlacklistService` is `Watchtower\Services\BlacklistService`.

## What has no equivalent

- **Allowlist-only mode** (`FirewallWhitelist`), as above.
- **Country blocking and GeoIP** (`country:` entries, `firewall:updategeoip`). Do it at the edge instead.
- **`host:` entries.** Watchtower never resolves DNS on a request.
- **Editing the allowlist at runtime.** `never_block` is config, so the whitelist can't be changed from the management page, the API or a facade call.
- **`firewall:clear`**, which emptied every list. Unblock from the management page instead.
