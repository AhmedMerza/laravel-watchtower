# Management API

[← Back to the README](../README.md) · [All docs](README.md)

For a standalone install, without LogScope.

A JSON management API mounts at `/watchtower/api/...` (configurable via `WATCHTOWER_ROUTE_PREFIX`) — `POST /api/block`, `DELETE /api/block/{ip}`, `GET /api/status/{ip}`, and a paginated, filterable [`GET /api/blocks`](#listing-blocks). A **[management page](management-page.md)** mounts at the same prefix — `/watchtower` — listing what is blocked, with a block form and an unblock that asks first, so the API is for your own scripts rather than the only way in.

**The API is closed outside `local` until you open it.** Access goes through a `viewWatchtower` Gate, which by default allows everyone in the `local` environment and no one anywhere else — the same model as Horizon and Pulse. Define it in your `AppServiceProvider` to decide who gets in:

```php
use Illuminate\Support\Facades\Gate;

public function boot(): void
{
    Gate::define('viewWatchtower', fn ($user) => in_array($user->email, [
        'admin@example.com',
    ]));
}
```

A Gate whose callback needs a `$user` refuses guests, so the routes need a session: keep `web` in `routes.middleware` (the default). That list can add middleware, such as `auth` or a throttle, but the Gate check is always applied after it. A refused request gets a 403, never a redirect. To turn the API off entirely, set `WATCHTOWER_ROUTES_ENABLED=false`. With LogScope installed, LogScope's own authorization applies instead: `viewWatchtower` is never evaluated and `routes.middleware` is never consulted — tighten access through LogScope's settings, not these.

## Listing Blocks

`GET /api/blocks` returns one page of blocks, newest first, with the same `source` and `state` filters the [management page](management-page.md) offers — they share one implementation, so the two lists can't answer the same question differently.

```
GET /watchtower/api/blocks?state=all&source=auto&per_page=50&page=2
```

| Parameter  | Values                              | Default  |
| ---------- | ----------------------------------- | -------- |
| `source`   | `manual`, `auto`, `sync`            | every source |
| `state`    | `active`, `expired`, `all`          | `active` |
| `per_page` | 1–100                               | 25       |
| `page`     | any page number                     | 1        |

The body is Laravel's standard paginator shape — the rows under `data`, the counts and page URLs beside it:

```json
{
  "current_page": 2,
  "data": [{ "id": "01J...", "ip": "203.0.113.50", "source": "auto", "expires_at": null }],
  "per_page": 50,
  "total": 87,
  "last_page": 2,
  "next_page_url": null,
  "prev_page_url": "https://example.com/watchtower/api/blocks?state=all&source=auto&per_page=50&page=1"
}
```

- **An unrecognised filter is ignored, not refused.** `?state=nonsense` lists active blocks rather than returning a 422 — a hand-edited query string shouldn't be an error page on the tool you reach for when something is wrong.
- **`per_page` is capped at 100.** Paginating is the point; without a ceiling, `?per_page=100000` is the unbounded query this endpoint used to be.
- **Page URLs keep your filters**, so paging through a filtered list doesn't silently widen it.
- **Expired blocks exist only until `watchtower:cleanup` next runs.** `?state=expired` can only show what's still there — "it expired an hour ago" and "it was never blocked" look identical once the row is gone.

**Authenticating a non-browser client isn't solved yet.** The management routes carry `watchtower.routes.middleware` (default `['web']`) and the `viewWatchtower` Gate, which is session-cookie authentication — fine for a browser, not for a mobile or CLI client. Token auth is deliberately not built: it needs decisions (which user a token resolves to, what `blocked_by` records for one, whether a token may create blocks or only read them) that shouldn't be guessed at without a real client to answer them. If you have one, say so on [#64](https://github.com/AhmedMerza/laravel-watchtower/issues/64). Until then, a script authenticates however the rest of your app does.
