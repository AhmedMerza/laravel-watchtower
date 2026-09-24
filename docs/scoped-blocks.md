# Scoped Blocks

[← Back to the README](../README.md) · [All docs](README.md)

Block an address from some routes only, such as your login routes, instead of the whole app.

A block normally covers the whole app. A **scoped** block covers only the routes you tag with it.

This is the middle option between blocking everyone behind a shared address and blocking nobody. Mobile carriers put thousands of subscribers behind one address, and offices and VPN exits do the same — so the [shared-IP guard](auto-block.md#shared-ips) downgrades a block on one to a warning, which also leaves the attacker among them free to carry on. A scoped block takes away the routes the evidence points at and leaves everyone else the rest of the app.

It takes **two changes, and neither does anything alone.**

**1. Declare the scope** in `config/watchtower.php`:

```php
'scopes' => ['auth'],
```

**2. Put the middleware on the routes it should cover.** Watchtower can't do this for you — only your app knows where its login routes are:

```php
// Laravel Breeze
Route::middleware('watchtower:auth')->group(function () {
    Route::post('/login', [AuthenticatedSessionController::class, 'store']);
    Route::post('/forgot-password', [PasswordResetLinkController::class, 'store']);
    Route::post('/reset-password', [NewPasswordController::class, 'store']);
});

// Laravel Fortify — wrap its routes, or set Fortify's own middleware config
Route::middleware('watchtower:auth')->group(function () {
    require base_path('vendor/laravel/fortify/routes/routes.php');
});
```

One route can name more than one scope: `watchtower:auth,admin` blocks an address blocked in either.

Then scope a block, by hand:

```bash
curl -X POST https://your-app.test/watchtower/api/block \
  -d 'ip=203.0.113.9' -d 'scope=auth'
```

…or from a rule or detector:

```php
'failed_logins' => [
    'enabled'        => true,
    'count'          => 10,
    'window_minutes' => 5,
    'scope'          => 'auth',
],
```

## What changes when a rule has a scope

A shared address that trips a **scoped** rule gets a scoped block instead of only a warning:

| | shared address trips the rule | one user trips it |
|---|---|---|
| no scope | warning only, attacker continues | blocked app-wide |
| `scope: auth` | **blocked on auth routes only** | blocked on auth routes only |

`warn` mode still only warns — a dry run stays a dry run whatever its scope — and `never_block` and `never_auto_block` are unchanged.

## Things worth knowing

- **Scopes default to off.** Every rule and detector ships with `'scope' => null`, meaning app-wide, exactly as before. Nothing changes for an existing install until you opt in.
- **A scope no route carries enforces nothing.** `php artisan watchtower:install` lists each declared scope and whether any route names it, and warns about the mirror mistake — a route naming a scope the config doesn't declare. A scope name that isn't declared is refused outright — a typo blocks nothing loudly rather than silently.
- **A scoped block is only ever enforced by the route middleware.** Nothing in the global stack acts on one, including the `scanner_paths` detector, which answers a probe itself when it blocks app-wide but not when it blocks in a scope.
- **Scoped blocks don't sync.** They stay on the node that made them: the sync payload has no scope field, and your satellites have their own route files. Tracked in [#37](https://github.com/AhmedMerza/laravel-watchtower/issues/37).
- **`GET /api/status/{ip}`** keeps `blocked` meaning *blocked app-wide*. Scoped blocks appear under a separate `scopes` key, so nothing reads a scoped block as a full one.
- **`DELETE /api/block/{ip}`** lifts every scope. Add `?scope=auth` to lift just one.
- **Cost:** a route without the middleware reads exactly the cache keys it always did. A scoped route reads two more, for that scope only.
