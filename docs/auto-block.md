# Auto-Block

[← Back to the README](../README.md) · [All docs](README.md)

Block addresses automatically, from real-time detectors or from rules over your logs. Everything here is off until you turn it on, and a dry run until you arm it.

Two ways to block automatically, sharing one set of guards:

- **Detectors** react to Laravel's own signals — a failed login, a login lockout, a probe for `/.env`, a burst of 404s, a scanner naming itself in its `User-Agent` — as they happen. No log table, **no LogScope**, and the block lands within the same request instead of on the next scheduled run.
- **Log rules** match patterns in LogScope's log table (`logscope.table`, default `log_entries`), evaluated every minute by the scheduler. These need LogScope installed.

Everything here is off unless you turn it on: auto-block itself is disabled, **every detector is disabled**, and `rules` ships empty.

> ⚠️ **Tune carefully or lock real users out.** An overly broad rule or detector can block legitimate traffic across every environment. **Both are a dry run by default** — they report what they would have caught and block nobody until you arm them.

```env
WATCHTOWER_AUTO_BLOCK_ENABLED=true
WATCHTOWER_AUTO_BLOCK_MODE=warn    # warn (default) | block | disabled
WATCHTOWER_AUTO_BLOCK_DURATION=60  # minutes
WATCHTOWER_SHARED_IP_USER_THRESHOLD=3
WATCHTOWER_ESCALATION=false              # longer blocks for repeat offenders
WATCHTOWER_ESCALATION_DECAY_DAYS=30
WATCHTOWER_NEVER_AUTO_BLOCK_IPS=203.0.113.0/24

# Detectors — all off by default, turn on one at a time
WATCHTOWER_DETECT_FAILED_LOGINS=false
WATCHTOWER_DETECT_LOGIN_LOCKOUTS=false
WATCHTOWER_DETECT_SCANNER_PATHS=false
WATCHTOWER_DETECT_RESPONSE_BURSTS=false
WATCHTOWER_DETECT_BAD_USER_AGENT=false
```

**Modes** (global default, overridable per rule *and* per detector):

| Mode | Behaviour |
|------|-----------|
| `warn` | **The default.** Match the rule and emit a structured `would_have_blocked: true` log entry on the configured log channel — but **do not** block. Tail your logs for that key to see what the rule would catch, then set `WATCHTOWER_AUTO_BLOCK_MODE=block` to arm it. |
| `block` | Actually block matching IPs. |
| `disabled` | Skip the rule entirely. A per-rule kill switch without deleting the definition. |

## Detectors

Each one counts per IP in the cache and blocks through the same path a rule does, so `never_block`, `never_auto_block` and the shared-IP guard all still apply. A request that matches nothing costs nothing — the middleware isn't even added to the stack unless a detector that reads the request is enabled.

| Detector | Signal | Default | Start at |
|---|---|---|---|
| `failed_logins` | `Illuminate\Auth\Events\Failed`, fired by every guard on a bad credential | off | 10 in 5 min |
| `login_lockouts` | `Illuminate\Auth\Events\Lockout`, fired by the Breeze / Fortify / `ThrottlesLogins` login throttle | off | 3 in 15 min |
| `scanner_paths` | A request for a configured path pattern | off | 1 in 5 min |
| `response_bursts` | Responses with a configured status (`404`, `429`) | off | 40 in 1 min |
| `bad_user_agent` | A request the [User-Agent filter](user-agents.md) already rejected | off | 5 in 10 min |

```php
'auto_block' => [
    'detectors' => [
        'failed_logins'  => ['enabled' => true, 'count' => 10, 'window_minutes' => 5],
        'login_lockouts' => ['enabled' => true, 'count' => 3,  'window_minutes' => 15],

        'scanner_paths' => [
            'enabled'        => true,
            'count'          => 1,
            'window_minutes' => 5,
            'patterns'       => ['/.env', '/.git/*', '/wp-login.php', '/xmlrpc.php', '/phpmyadmin*'],
        ],

        // Armed only after watching it in warn mode for a full traffic cycle
        'response_bursts' => [
            'enabled'        => true,
            'count'          => 40,
            'window_minutes' => 1,
            'statuses'       => [404, 429],
            'mode'           => 'warn',
        ],

        // Escalates the User-Agent filter from rejecting each request to
        // blocking the address behind them
        'bad_user_agent' => ['enabled' => true, 'count' => 5, 'window_minutes' => 10],
    ],
],
```

A few things worth knowing before you arm any of these:

- **`scanner_paths` answers the matching request itself.** A probe for `/.env` gets the block response rather than your 404, so a pattern that overlaps a real route never serves it even once. That cuts both ways: **a pattern that overlaps a route your users need will lock them out of it**, so keep the list to paths nothing legitimate asks for. Matching runs against the *decoded* path, so `/%2Eenv` is caught too. The threshold of `1` is deliberate — a single request for `/.env` is not a mistake.
- **`response_bursts` is the loosest and most likely to catch a real person.** It reads the status after the response is sent, so it costs the request nothing, but a broken deploy that 404s its own assets looks exactly like enumeration. Leave it in `warn` mode for a full traffic cycle and raise the count to whatever your own logs say is normal.

  **A route whose 404 means "found nothing" trips it too.** A search, a lookup by a code someone typed, or a front end polling for a record that doesn't exist yet can produce dozens of 404s a minute from one signed-in user. The real fix is to return `200` with an empty result from those routes. Until you can, list them in `except_paths`, using the same pattern syntax as `scanner_paths` and matched against the decoded path, case-insensitively. Their 404s and 429s are then never counted:

  ```php
  'response_bursts' => [
      // ...
      'except_paths' => ['/api/lookup/*', '/search'],
  ],
  ```

  Keep the list to routes like these. A route that takes an ID is exactly what enumeration walks, so excepting it hides the burst this detector exists to catch. Skipping signed-in users instead would not be safer: a stolen session enumerating IDs is a signed-in user.
- **`bad_user_agent` only sees what the filter already rejected**, so it does nothing unless `user_agents` is on, and a `never_block` address never reaches it. Its threshold is `5` rather than `scanner_paths`' `1` because a `User-Agent` is one header anyone can set to anything — see [Attack-Tool User-Agents](user-agents.md).
- **`login_lockouts` builds on a limit you already set.** It counts the throttle your login form already applies, so one lockout is someone fumbling a password and several is someone working through a list.
- **The counter resets on every decision**, so a block that lapses doesn't re-fire on the next signal.
- **A detector that decides to block and is held back from doing it reports once, not once per request.** A real block takes the address away from the detector entirely — a blocked scanner never reaches the counter again — and nothing did that for a decision that was only *reported*: `warn` mode, or a `never_auto_block` refusal. So the address kept arriving and kept being re-decided, which at `scanner_paths`' `count` of `1` meant a log line for every probe. The decision is now held for `block_duration_minutes` — the same span the block would have covered — and the detector ignores the address until it lapses, so a `warn`-mode log reads as one entry per block it predicts rather than one per request. **Arming a detector still takes effect on the very next request** rather than waiting the hold out, because the hold records the mode it was opened under. Taking an address *off* `never_block` or `never_auto_block` takes effect on its next threshold crossing, too: the hold records which guard held the decision back, and a `never_*` refusal — which names one address, while the hold covers the prefix a block would have — is re-checked against the list for the address now asking, so one exempt entry can't shield the rest of its `/64`. The entry still carries the `hits` that crossed the threshold, but that is a count of what it took to decide, not of everything the address sent — for that, read the traffic where it lands, in your web server log or LogScope.
- **A [shared-IP](#shared-ips) hold is the exception: it is re-measured, never held.** `warn` mode and `never_auto_block` are settings that will say the same thing in an hour; how many signed-in users an address is showing is not. Holding that answer would turn a guard an attacker has to keep re-earning into an hour of immunity bought once — so a shared address is re-counted on every crossing, and blocks on the first one where the accounts have stopped appearing.
- **`scanner_paths` at `count: 1` means one request is enough to block.** Every other path to a block needs accumulation. That is deliberate for paths nothing legitimate requests, but it also means a **misconfigured trusted proxy** — one that forwards a client-supplied `X-Forwarded-For` verbatim — lets an attacker name an innocent address and get it blocked with a single crafted request. Watchtower warns when `TrustProxies` is missing entirely, but it cannot detect an overly-permissive one. Get proxy trust right before arming this.
- **Toggling a detector's `enabled` flag takes effect at boot, not live.** Its `count`, `window_minutes`, `mode` and `patterns` are re-read on every signal, but whether a detector is wired up at all is decided when the provider boots. Under Octane, Swoole, RoadRunner or a long-lived queue worker, switching one on or off needs a worker restart.

## Shared IPs

Plenty of real users share one public address: mobile carriers put subscribers behind carrier-grade NAT, and offices, universities and VPN exits do the same. Count errors per IP and a rule tuned to catch **one** bad actor ends up blocking **everyone** behind that gateway.

So before it blocks, watchtower counts how many **distinct signed-in users** the log saw from that address during the window. At or above `WATCHTOWER_SHARED_IP_USER_THRESHOLD` (default `3`) the block downgrades to a warning carrying `not_blocked_because: shared IP`. Set the threshold to `0` to switch the guard off.

The count covers **all** of the address's logged traffic, not just the rows the rule matched — the question is how many people a block would hit, not how many of them tripped it. An address where one buggy client throws every error while two hundred others browse fine is the case this exists for.

**Detectors have no log table to ask**, so they count the signed-in users seen on the requests they themselves counted, and the `would_have_blocked` entry carries the actual `user_ids` alongside `distinct_users` — deciding whether to arm a detector is much easier when you can see *who* was behind a flagged address rather than just how many. Nothing is recorded for traffic that matches no detector.

**The same caveat applies, and more sharply.** The guard counts signed-in users and can't tell real ones from accounts an attacker made — and for detectors the identity comes from the *matching* requests themselves, so an attacker doesn't even need separate innocent traffic: signing in as three throwaway accounts while probing is enough to downgrade `response_bursts` to warn-only for their address. Read the guard as protection against **your own detector misfiring on a real shared gateway** — a broken deploy 404ing assets for three signed-in staff, which it handles exactly right — and never as a control an adversary respects. For that, use `never_block`, or keep `scanner_paths` at its default `count` of `1`, which fires before any accumulation is possible.

That makes the guard strongest for `response_bursts`, where the requests are often signed in, and **blind for `failed_logins` and `login_lockouts`**, where by definition nobody is. It would be easy to count the account the credentials were *aimed* at instead — and wrong: an attacker working through a list of usernames would report a new distinct "user" on every attempt, read as a busy office, and stand the guard down. The guard would be disarmed by exactly the attack it is in the way of. So those two detectors report no users at all, and **`never_auto_block` is the protection for a known office or carrier range** before you arm them.

Limits worth knowing:

- **It can be gamed wherever anyone can sign up.** The guard counts signed-in users; it cannot tell real ones from accounts an attacker made. Where registration is open, someone who authenticates three throwaway accounts from their own address — one harmless request each is enough — downgrades every auto-block against that address to a warning, and the attack traffic itself needn't be signed in at all. Raise `WATCHTOWER_SHARED_IP_USER_THRESHOLD` above what an attacker will bother creating, and treat the guard as protection against *your own rules misfiring*, not as a control an adversary respects. When you need a decision automation can't be argued out of, that's `never_block`.
- It only sees users your app actually logged. It protects an address your users are signed in from; it can't recognise a busy gateway whose traffic is all anonymous.
- Anonymous traffic counts for nobody, so a scanner hitting you while signed out still gets blocked. That is deliberate.

For gateways the guard can't see, list them explicitly:

```env
WATCHTOWER_NEVER_AUTO_BLOCK_IPS=203.0.113.0/24,2001:db8:2::/48
```

`never_auto_block` binds automation only — **an admin can still block a listed address by hand**, through the UI or the API. That is the whole difference from `never_block`, which nothing can override. Use `never_auto_block` for "a rule would be right about this traffic and wrong about the people behind it", and `never_block` for "never, under any circumstances".

**It survives sync in both directions.** The sync payload carries what decided
each block, so a receiving node applies its own `never_auto_block` to a block
another environment's *rule* made, while still accepting one an admin there
made by hand — which is the distinction the list exists for. `never_block` is
enforced on every synced block regardless, as it always was.

> ⚠️ **One node at a time, during an upgrade.** A satellite running a version
> older than 0.6.0 doesn't send that field, and a node that can't tell what
> decided a block treats it as unknown rather than as automation — so an old
> satellite keeps syncing exactly as it does today, and its admins' manual
> blocks keep working. `never_auto_block` starts covering that satellite's
> automated blocks once it is upgraded. `watchtower:sync` counts what it turns
> away as `refused by never_auto_block`, separately from `never_block`.

## Escalating durations

An hour is a pause, not a deterrent, for someone who comes back. Turn this on and an address that earns a **second** auto-block gets a longer one, and a third longer again.

```env
WATCHTOWER_ESCALATION=true
WATCHTOWER_ESCALATION_DECAY_DAYS=30
```

```php
'escalation' => [
    'enabled'          => env('WATCHTOWER_ESCALATION', false),
    'repeat_durations' => [360, 1440, 10080],   // minutes
    'decay_days'       => env('WATCHTOWER_ESCALATION_DECAY_DAYS', 30),
],
```

The **first** auto-block always lasts `block_duration_minutes`. `repeat_durations` is the 2nd, 3rd, 4th… and its last value repeats from then on, so the defaults above read: **1 hour → 6 hours → 1 day → 1 week** for every offence after that. Keeping the first block out of the list is what stops two settings claiming the same number — switching escalation on can lengthen a block, never shorten one.

**The count decays.** An address that goes quiet for `decay_days` starts again at the bottom, so an address reassigned to somebody else isn't serving the last tenant's sentence. `watchtower:cleanup` forgets those ledgers on its next run.

**What doesn't escalate:**

| | Why |
|---|---|
| A `warn`-mode near miss | A dry run has to stay one. Arming a rule later would otherwise hand out six-hour blocks on the strength of blocks that never happened. |
| An address held back for being shared | It wasn't blocked, so it didn't offend. A shared address downgraded to a **scoped** block *was* blocked, and does count. |
| Manual blocks, and blocks arriving over sync | Both carry the duration their caller asked for. Only the auto-block engine consults the ladder. |

The count lives in the `ip_offences` table, one row per address per scope, so it survives `cache:clear` — and each scope keeps its own ladder. Two offences on your login routes don't decide how long an app-wide block lasts.

> Counts are **per environment**. Sync carries blocks, not ledgers, so a satellite that has seen one offence won't inherit the master's count. That is deliberate: the offence happened where it happened.

## Log rules

These read LogScope's log table, so they need LogScope installed — and they only see what your app actually logged, which is why Laravel's own 404s are invisible to them and `scanner_paths` exists. Define them in `config/watchtower.php`:

```php
'auto_block' => [
    'enabled'                  => env('WATCHTOWER_AUTO_BLOCK_ENABLED', false),
    'mode'                     => env('WATCHTOWER_AUTO_BLOCK_MODE', 'warn'),
    'shared_ip_user_threshold' => env('WATCHTOWER_SHARED_IP_USER_THRESHOLD', 3),
    'block_duration_minutes'   => 60,
    'rules' => [
        // Armed: block IPs that generate 50+ errors in 5 minutes
        [
            'level'            => 'error',
            'message_contains' => null,
            'count'            => 50,
            'window_minutes'   => 5,
            'mode'             => 'block',
        ],
        // Still a dry run — no 'mode', so it follows the 'warn' default
        [
            'level'            => 'warning',
            'message_contains' => '404',
            'count'            => 100,
            'window_minutes'   => 10,
        ],
    ],
],
```

Rules run every minute via the scheduler — detectors don't need it, since they act inside the request. Add the scheduler to your server if not already running:

```bash
* * * * * cd /your-app && php artisan schedule:run >> /dev/null 2>&1
```

> **Note:** IPs in `WATCHTOWER_NEVER_BLOCK_IPS` are never auto-blocked, even if they match a rule. Those in `WATCHTOWER_NEVER_AUTO_BLOCK_IPS` are skipped by automation but remain blockable by hand.

**A rule held back from blocking reports once per block it predicts, not once per tick** — the same hold the [detectors](#detectors) get. A blocked address drops out of a rule's offenders; in `warn` mode, or for a `never_auto_block` address, nothing blocks, so its rows kept matching and it was re-reported every minute for as long as they stayed in the window. The decision is now held for `block_duration_minutes`, which is also what [`watchtower:simulate`](#backtesting-a-rule-before-you-arm-it) assumes, so a dry run and a backtest of the same rule agree. Arming a rule takes effect on the next tick, a shared-IP warning is re-measured rather than held, and the hold is kept per rule by what it matches and where it blocks rather than by its position in the list — editing a rule's `level`, `message_contains`, `count`, `window_minutes` or `scope` makes it a new rule whose first crossing is reported afresh.

## Backtesting a rule before you arm it

`warn` mode is the honest way to try a rule out, and it costs days: set it,
wait, read logs. `watchtower:simulate` skips the waiting, because LogScope
already kept the history the rule would have read:

```
Rule #0 — level=error, 10 hit(s) in 5 min [block]
  1 address(es) would have been blocked, 1 block(s) in total.
+--------------+--------+------------------+------------------+-------+-----------------+-------------+
| IP           | Blocks | First            | Last             | Users | Clean signed-in | Guard       |
+--------------+--------+------------------+------------------+-------+-----------------+-------------+
| 198.51.100.4 | 1      | 2026-09-21 10:30 | 2026-09-21 10:32 | 4     | 4               | 2 held back |
+--------------+--------+------------------+------------------+-------+-----------------+-------------+
  1 of these also sent signed-in traffic that never matched the rule — a block would have taken that away too.
  1 would have been held back by the shared-IP guard (>= 3 signed-in users): 2 warning(s), one a minute while it looked shared.
```

The two warning lines are the point. **Clean signed-in** counts requests from
that address that carried a signed-in user and never matched the rule — people
who were doing nothing wrong and would have lost access anyway. **Guard** counts
the minutes the shared-IP guard would have held a block back, each computed
against the window the live guard would actually have read at that moment, not
the whole period. The guard is re-measured every minute, as the engine does it,
so an address can be held back and then blocked once its signed-in users age
out of the window — as `198.51.100.4` was at 10:32. **First** and **Last** are
its first and last crossing either way.

It needs LogScope's log table and reports on whatever history is there, so a
fresh install has nothing to say until logs accumulate. It reports every
configured rule regardless of `auto_block.enabled` or a rule's `mode` — the
reason you are running it is to decide those.

It knows what the engine knows. A rule whose `scope` isn't declared in
`watchtower.scopes` is skipped by the engine, so it is reported as skipped
rather than simulated. Addresses covered by `never_block` or
`never_auto_block` are listed separately instead of counted as would-be
blocks, because the engine refuses those whatever a rule says. And on a
*scoped* rule the shared-IP guard doesn't hold a block back — it narrows it
to that scope — so the report says "scoped", not "warning".

**Two deliberate inexactnesses, both erring towards over-reporting.** The
engine evaluates rules on a one-minute scheduler tick; the replay walks the
rows and notices a crossing at the row that caused it, up to a minute
earlier. And escalating durations are not modelled — every simulated block
lasts `block_duration_minutes`, so an address that would have earned a
longer second block shows slightly more blocks here than it got. Rules are
also replayed independently, while the live engine skips an address another
rule has already blocked, so two overlapping rules can both claim the same
address. Nor is a block's reach modelled: the engine blocks an IPv6 address's
whole `/64`, which keeps its siblings out for the duration, while the replay
judges each address on its own rows — so a sibling that kept going shows
blocks the live `/64` block would already have covered.

### Cost, honestly

Memory is bounded: each address is replayed through a ring buffer holding at
most `count` timestamps, so one that logged a million rows costs the same as
one that logged fifty.

Query cost is a different matter, and worth knowing before you point this at
a large table. The narrowing pass admits any address with `count` matching
rows *anywhere in the period* — a much weaker filter than "`count` inside one
window" — so on busy traffic it admits many addresses that never actually
trip the rule, and each one is then streamed individually. LogScope has no
`(ip_address, occurred_at)` index, so those per-address reads have no ideal
plan. An address that crosses the threshold while the shared-IP guard is on
is read once more — its signed-in rows, streamed alongside the replay to keep
a running count of users in the window — so the guard adds one walk per
address, not one query per simulated minute.

If you run this regularly against a large `log_entries`, add the composite
index:

```php
Schema::table('log_entries', fn (Blueprint $t) => $t->index(['ip_address', 'occurred_at']));
```

It is a write cost on LogScope's hottest table, so measure before you keep
it. Start with a small `--days` and widen.
