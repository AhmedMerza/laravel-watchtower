# Management Page

[← Back to the README](../README.md) · [All docs](README.md)

A page at `/watchtower` that lists what is blocked, and blocks and unblocks by hand. No build step and no JavaScript.

A page at your route prefix — `/watchtower` by default — lists what is blocked and lets you block and unblock by hand.

- **The blocklist**, newest first: address or range, scope, source (`manual`, `auto` or `sync`) and the environment it came from, reason, who blocked it, when it was blocked and when it expires. 25 to a page.
- **Filters** by source and by active / expired / all. They live in the query string, so a filtered list is a link you can send someone — and expired blocks are worth looking at, because `watchtower:cleanup` eventually deletes those rows and "it expired an hour ago" then becomes indistinguishable from "it was never blocked".
- **A block form**: an IP or a CIDR range, a reason, and 1 hour / 24 hours / 7 days / permanent. Where you have declared [scopes](scoped-blocks.md), it can block an address from those routes only. Blocking a range wider than IPv4 `/16` or IPv6 `/32` needs the checkbox, the same guard `POST /api/block` applies.
- **Unblock, which asks first.** It lifts exactly the row you clicked: an address with both an app-wide block and a scoped one is two rows, and lifting one leaves the other. (`DELETE /api/block/{ip}` still lifts every scope, because "unblock this address" has to keep meaning the address can use the app again.)
- When LogScope is installed, a block made from a log entry links back to that entry.

It is behind **the same authorization as the API** — the `viewWatchtower` Gate in a standalone install, LogScope's own check when LogScope is present — and there is no setting that exposes the page without the API or the other way round.

The page mounts in **both** modes; with LogScope installed it sits at `/logscope/watchtower`. From LogScope 2.2.0 it is the only place to block by hand from a browser, because LogScope no longer shows a Block IP button. On 1.6.1–2.1.x that button acts on one address at a time from a log entry and has no list of what is blocked, so an install with LogScope needs this page either way.

**No build step, and nothing loaded from the network.** It is server-rendered Blade with one inline stylesheet and no JavaScript at all — no npm, no CDN, no published assets to keep in step with an upgrade, and it works on a host with no outbound access. The unblock confirmation is a round trip rather than a dialog, so the page needs no `script-src` exception; a strict CSP does need `style-src 'unsafe-inline'` for the stylesheet. It follows the operating system's light or dark setting.

Keep the JSON API and drop the page with:

```env
WATCHTOWER_UI_ENABLED=false
```

To restyle it, publish the views and edit them:

```bash
php artisan vendor:publish --tag=watchtower-views
```
