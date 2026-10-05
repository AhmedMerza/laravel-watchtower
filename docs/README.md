# Watchtower docs

[← Back to the README](../README.md)

| Page | What it covers |
|---|---|
| [Configuration](configuration.md) | Every `.env` setting, the block response, IP ranges and IPv6, the webhook |
| [Management API](api.md) | The JSON endpoints, who can reach them, and listing blocks page by page |
| [Management Page](management-page.md) | The built-in page for listing, blocking and unblocking by hand |
| [Cross-Environment Sync](sync.md) | Sharing blocks between production, staging and the rest |
| [Block Targets](block-targets.md) | Pushing a block to Cloudflare or an nginx deny file, so it's turned away before Laravel boots |
| [Public Blocklist Feeds](feeds.md) | Importing Spamhaus DROP or FireHOL level1 daily, and what an import never touches |
| [Attack-Tool User-Agents](user-agents.md) | Rejecting sqlmap, Nikto and friends, and verifying search bots |
| [Auto-Block](auto-block.md) | Detectors, log rules, modes, the shared-IP guard, escalation, and backtesting with `watchtower:simulate` |
| [Scoped Blocks](scoped-blocks.md) | Blocking an address from some routes only |
| [Artisan Commands](commands.md) | `install`, `sync`, `cleanup`, `simulate`, `reconcile`, `import-feeds`, `import-firewall` |
| [Migrating from antonioribeiro/firewall](migrating-from-firewall.md) | Importing its blocks and allowlist, and what replaces its middleware and facade |
| [Upgrading](upgrading.md) | What to check when you upgrade |
| [Security Notes](security.md) | Proxies, cache outages, request signing |
