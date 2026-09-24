# Artisan Commands

[← Back to the README](../README.md) · [All docs](README.md)

The four commands Watchtower adds.

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

# Backtest the auto-block rules against the log history you already have.
# Read-only — it writes nothing, whatever mode the rules are in.
php artisan watchtower:simulate --days=7
php artisan watchtower:simulate --rule=0 --json
```

To backtest your rules, see [Backtesting a rule before you arm it](auto-block.md#backtesting-a-rule-before-you-arm-it).
