# Configuration

[← Back to the README](../README.md) · [All docs](README.md)

Every setting, with the `.env` variable that controls it. The published `config/watchtower.php` documents each one inline too.

```env
# Master switch
WATCHTOWER_ENABLED=true

# IPs and CIDR ranges that can never be blocked (comma-separated) — prevents self-lockout
WATCHTOWER_NEVER_BLOCK_IPS=127.0.0.1,::1,10.0.0.0/8

# Blocking one IPv6 address blocks the network around it, this many bits long (32–128; 128 = exact address only)
WATCHTOWER_IPV6_BLOCK_PREFIX=64

# Cache store for the blocklist. Blank = your app's default cache store.
# Any Laravel driver works: redis, memcached, file, database, array, dynamodb.
WATCHTOWER_CACHE_STORE=

# Management routes (standalone mode)
WATCHTOWER_ROUTES_ENABLED=true
WATCHTOWER_ROUTE_PREFIX=watchtower
# WATCHTOWER_ROUTE_DOMAIN=admin.example.com

# Cross-environment sync
WATCHTOWER_MASTER_URL=https://your-master-app.com
WATCHTOWER_SYNC_SECRET=a-long-random-secret
WATCHTOWER_SYNC_ROLE=satellite  # master on the master; see docs/sync.md
WATCHTOWER_SYNC_TOLERANCE=300   # seconds a signed request stays valid
WATCHTOWER_SYNC_QUEUE=          # queue the push-to-master job runs on;
                                # falls back to WATCHTOWER_NOTIFICATION_QUEUE, then 'default'

# Auto-block engine (disabled by default)
WATCHTOWER_AUTO_BLOCK_ENABLED=false
WATCHTOWER_AUTO_BLOCK_MODE=warn    # warn (default) | block | disabled
WATCHTOWER_AUTO_BLOCK_DURATION=60
WATCHTOWER_SHARED_IP_USER_THRESHOLD=3   # distinct signed-in users before a block downgrades to a warning; 0 disables
WATCHTOWER_NEVER_AUTO_BLOCK_IPS=        # automation skips these; an admin can still block them by hand

# Real-time detectors (all disabled by default; no LogScope needed)
WATCHTOWER_DETECT_FAILED_LOGINS=false     # Auth\Events\Failed      — start at 10 in 5 min
WATCHTOWER_DETECT_LOGIN_LOCKOUTS=false    # Auth\Events\Lockout     — start at 3 in 15 min
WATCHTOWER_DETECT_SCANNER_PATHS=false     # /.env, /.git/*, …       — start at 1 in 5 min
WATCHTOWER_DETECT_RESPONSE_BURSTS=false   # 404 bursts              — start at 40 in 1 min
WATCHTOWER_DETECT_BAD_USER_AGENT=false    # rejected User-Agents    — start at 5 in 10 min

# Reject requests whose User-Agent names a known attack tool (ON by default)
WATCHTOWER_USER_AGENT_FILTER=true
WATCHTOWER_VERIFY_SEARCH_BOTS=false       # forward-confirmed reverse DNS for Googlebot/Bingbot claims
                                          # ⚠️ blocking DNS on the request path — see the section below

# Webhook notification on every block (optional — useful for n8n, Slack, WhatsApp)
WATCHTOWER_WEBHOOK_URL=
WATCHTOWER_NOTIFICATION_QUEUE=default   # a worker must consume this queue, or the
                                        # webhook is queued where nothing sends it

# Dedicated log channel for Watchtower events (sync failures, auto-block skips, etc.)
WATCHTOWER_LOG_CHANNEL=stack

# Automatic cleanup of expired temporary blocks (runs daily)
WATCHTOWER_CLEANUP_ENABLED=true

# Public blocklist feeds, imported daily (all off by default) — see docs/feeds.md
WATCHTOWER_FEED_SPAMHAUS_DROP=false
WATCHTOWER_FEED_FIREHOL_LEVEL1=false
```

## Block Response

By default, blocked IPs receive a plain-text `403 Access denied.` response. It's returned directly, so the app's exception handler never sees it: no custom `errors/403` page, and no JSON body for API clients. To redirect instead:

```php
// config/watchtower.php
'block_response' => [
    'status'   => 403,
    'message'  => 'Access denied.',
    'redirect' => null, // Set a URL to redirect instead
],
```

## IP Ranges and IPv6

A block can be a single IP or a CIDR range, from the management page, the API, auto-block or sync:

```json
POST /watchtower/api/block
{ "ip": "203.0.113.0/24", "reason": "hosting range" }
```

- **Ranges are stored as their network address**, so `203.0.113.77/24` is stored as `203.0.113.0/24`.
- **One IPv6 address blocks its /64.** An IPv6 client usually controls a whole /64 and can move to another address inside it at will, so blocking `2001:db8:1:2::9` stores and blocks `2001:db8:1:2::/64`. Change the width with `WATCHTOWER_IPV6_BLOCK_PREFIX`. To block exactly one IPv6 address, send it as `/128`.
- **Very broad ranges need `force`.** IPv4 ranges shorter than /16 and IPv6 ranges shorter than /32 get a 422 unless the request also sends `force=true`. A master accepts whatever its satellites push, since they already made that call.
- **`WATCHTOWER_NEVER_BLOCK_IPS` accepts ranges** and always wins: an address it covers gets through even when a blocked range covers it too. A block is refused only when the never-block list covers all of it.
- **Unblocking an IP lifts its own block**, including the /64 that blocking it created, but never a wider range that covers it. `DELETE /api/block/{ip}` and `GET /api/status/{ip}` take a range too (`/api/block/203.0.113.0/24`), and the status of an IP names the range blocking it.

Single IPs, and IPv6 networks at the configured prefix (which is everything auto-block creates), are one cache key each. Every other range sits in one list that each request reads, so a request makes two cache reads however many blocks there are.

## Webhook Notification

With `WATCHTOWER_WEBHOOK_URL` set, every block made on this environment — manual, auto-block, or a block a satellite pushes to this master — is posted to that URL as JSON from a queued listener. Blocks a satellite pulls with `watchtower:sync` don't trigger it, so each block is announced once, by the environment that received it.

```json
{
  "ip": "203.0.113.50",
  "reason": "credential stuffing",
  "source": "manual",
  "source_env": "production",
  "blocked_by": "admin@example.com",
  "expires_at": null,
  "blocked_at": "2026-09-17T08:00:00+00:00"
}
```

`source` is `manual`, `auto` or `sync`, and `expires_at` is `null` for a permanent block. The request is unsigned and isn't retried: a connection failure is logged on `WATCHTOWER_LOG_CHANNEL`, and an error response is ignored.

## Alerts (mail, Slack, any notification channel)

Watchtower can send a Laravel notification each time it auto-blocks an address. Alerts are off by default, and the webhook above works either way.

```dotenv
WATCHTOWER_ALERTS=true
WATCHTOWER_ALERT_MAIL=ops@example.com,oncall@example.com
# WATCHTOWER_ALERT_SLACK_WEBHOOK=https://hooks.slack.com/services/...
```

A channel is on when its route has a value. Mail goes out through your app's own mailer. Slack takes an incoming-webhook URL and needs `composer require laravel/slack-notification-channel`. Alerts are queued on `WATCHTOWER_NOTIFICATION_QUEUE`, so a worker has to be consuming that queue. If an alert can't be sent, it's logged on `WATCHTOWER_LOG_CHANNEL` and the block still stands.

Each alert gives the address, the reason, which detector or rule fired, the scope, when the block expires, and a link to the [management page](management-page.md) when the UI is on. The link is built from `APP_URL`, so set it to the app's public address.

| Setting | Env | Default | |
|---|---|---|---|
| `throttle_minutes` | `WATCHTOWER_ALERT_THROTTLE_MINUTES` | `60` | Sends at most one alert per address and scope in this window. An IPv6 address counts as its /64, the same as a block does. Blocks and near misses are counted separately. `0` sends every one and also turns off the cap below. |
| `max_per_window` | `WATCHTOWER_ALERT_MAX_PER_WINDOW` | `20` | Sends at most this many alerts of each kind per window across all addresses, so a scanner rotating through a thousand addresses sends 20 alerts, not a thousand. Reaching the cap is logged on `WATCHTOWER_LOG_CHANNEL`. `0` means no cap. |
| `manual` | `WATCHTOWER_ALERT_MANUAL` | `false` | Also alerts on blocks made by hand. Blocks from sync and feeds never alert. |
| `would_have_blocked` | `WATCHTOWER_ALERT_WOULD_HAVE_BLOCKED` | `false` | Also alerts on near misses: the same events as the `would_have_blocked` log line (warn mode, the shared-IP guard, `never_auto_block`), each with why nothing was blocked. Useful while a warn-mode round is running. |

### Daily digest

The digest is one message a day listing every block and near miss since the previous digest, grouped by address. Each address shows how many times it was hit, when it was first and last seen, and how many of its events the throttle or the cap kept from alerting at the time. Instant alerts drop anything over the cap, and the digest is where those dropped alerts get reported.

```dotenv
WATCHTOWER_ALERT_DIGEST=true
# WATCHTOWER_ALERT_DIGEST_AT=08:00
# WATCHTOWER_ALERT_INSTANT=false
```

The digest uses the same routes as the instant alerts and is sent by `watchtower:alert-digest`, which is scheduled daily at `at` in the app timezone. Before turning it on:

- Laravel's scheduler must be running.
- Publish and run the `watchtower_alert_digest` migration.

Each event is stored as one row until the digest that reports it goes out. If the digest can't be sent on any channel, the rows are kept and the next run reports them. The digest lists the 50 busiest addresses and counts the rest.

| Setting | Env | Default | |
|---|---|---|---|
| `digest.enabled` | `WATCHTOWER_ALERT_DIGEST` | `false` | Records events and schedules the digest. Needs `WATCHTOWER_ALERTS=true`. |
| `digest.at` | `WATCHTOWER_ALERT_DIGEST_AT` | `08:00` | The time of day the digest is sent. |
| `digest.instant` | `WATCHTOWER_ALERT_INSTANT` | `true` | `false` sends only the digest, with no instant alerts. |
| `digest.notification` | | `BlockDigest::class` | The notification class to send. For another channel, extend `BlockDigest` the way the next section extends `BlockAlert`. |

### Another channel

To use any other notification channel, extend `BlockAlert`, add that channel's `toX()` method, and give it a route. `subject()` and `lines()` hold the text the built-in channels send. For example, with a Telegram notification channel package installed:

```php
class WatchtowerAlert extends \Watchtower\Notifications\BlockAlert
{
    public function toTelegram(object $notifiable): TelegramMessage
    {
        return TelegramMessage::create()->content($this->subject()."\n".implode("\n", $this->lines()));
    }
}
```

```php
// config/watchtower.php → notifications.alerts
'routes'       => ['mail' => env('WATCHTOWER_ALERT_MAIL'), 'telegram' => env('TELEGRAM_CHAT_ID')],
'notification' => App\Notifications\WatchtowerAlert::class,
```

The same subclass can also reword the built-in messages, by overriding `subject()`, `lines()`, `toMail()` or `toSlack()`.
