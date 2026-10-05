# Artisan Commands

[← Back to the README](../README.md) · [All docs](README.md)

The commands Watchtower adds.

```bash
# First-time setup (publish config + run migration)
php artisan watchtower:install

# Pull blacklist from master and rebuild the local cache
php artisan watchtower:sync

# Delete expired temporary blocks and rebuild the cache
# Also forgets offence ledgers that have decayed (see Escalating durations)
# Runs automatically every day — set WATCHTOWER_CLEANUP_ENABLED=false to manage manually
# Permanent blocks (no expiry) are never touched
php artisan watchtower:cleanup

# Push the full active (global) blocklist to every enabled block target —
# today that's the master environment, if WATCHTOWER_MASTER_URL is set.
# Repairs drift a live push missed; not scheduled by default.
php artisan watchtower:reconcile

# Import the enabled public blocklist feeds, replacing the previous import.
# Runs automatically every day; every feed is off until you enable it.
# Never touches manual, auto or sync blocks.
php artisan watchtower:import-feeds
php artisan watchtower:import-feeds --force   # accept a feed that shrank by more than half

# Import antonioribeiro/firewall's blocks. A dry run unless --commit;
# prints its whitelist for never_block. Safe to re-run.
php artisan watchtower:import-firewall
php artisan watchtower:import-firewall --commit

# Backtest the auto-block rules against the log history you already have.
# Read-only — it writes nothing, whatever mode the rules are in.
php artisan watchtower:simulate --days=7
php artisan watchtower:simulate --rule=0 --json
```

To turn on a feed, see [Public Blocklist Feeds](feeds.md).

To move off antonioribeiro/firewall, see [Migrating from antonioribeiro/firewall](migrating-from-firewall.md).

To backtest your rules, see [Backtesting a rule before you arm it](auto-block.md#backtesting-a-rule-before-you-arm-it).
