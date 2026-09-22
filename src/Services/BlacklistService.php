<?php

declare(strict_types=1);

namespace Watchtower\Services;

use Illuminate\Support\Collection;
use Watchtower\Enums\BlockSource;
use Watchtower\Events\IpBlocked;
use Watchtower\Exceptions\NeverAutoBlockException;
use Watchtower\Exceptions\NeverBlockException;
use Watchtower\Jobs\PushBlockToMaster;
use Watchtower\Models\BlacklistedIp;
use Watchtower\Support\BlockScope;
use Watchtower\Support\IpRange;
use Watchtower\Support\NeverBlockList;

class BlacklistService
{
    public function __construct(private readonly BlacklistCache $cache) {}

    /**
     * Block an IP or CIDR range. Normalizes the target, enforces the
     * never-block whitelist, writes to DB, writes the cache entry, fires the
     * IpBlocked event, and dispatches a push job to the master environment
     * (if configured).
     *
     * A single IPv6 address is stored as its configured prefix
     * (`ipv6_block_prefix`, /64 by default), since the client can hop to
     * any other address inside it.
     *
     * A single address costs one cache key; only a range pays for a full
     * rebuild. See BlacklistCache::write(), which also keeps the entry
     * correct when the DB read behind a rebuild fails — the middleware only
     * reads the cache, and would otherwise let the IP through while every
     * caller is told it was blocked.
     *
     * @throws NeverBlockException when the never-block whitelist covers what was asked for
     * @throws NeverAutoBlockException when automation aims at the never-auto-block list
     */
    public function block(string $ip, array $options = []): BlacklistedIp
    {
        // Checked before widening: never_block protects the address asked
        // for. The rest of its /64 is still blocked, and the middleware
        // lets the whitelisted address through regardless.
        $this->assertBlockable($ip);

        // never_auto_block binds automation only, so it is checked against
        // the source rather than the address alone: the same call an admin
        // makes by hand goes through. Living here rather than in each
        // detector means a new automated path can't forget it.
        //
        // The string form is resolved first because the model's enum cast
        // accepts one, so `'source' => 'auto'` persists as an auto block
        // while a strict enum comparison would wave it past this guard.
        // A block arriving from another node does not come through here at
        // all — applySync() is its one entry point, and it applies this same
        // list against the `origin_source` the sender now reports (#56).
        $source = $options['source'] ?? BlockSource::Manual;

        if (is_string($source)) {
            $source = BlockSource::tryFrom($source);
        }

        if ($source === BlockSource::Auto && $this->isNeverAutoBlock($ip)) {
            throw new NeverAutoBlockException("{$this->normalizeIp($ip)} is in the never-auto-block list; automation cannot block it, but an admin can.");
        }

        // Resolved before the write, so a name the config doesn't declare is
        // refused rather than stored. A block scoped to a name no route
        // carries enforces nothing while reporting itself as a block, which
        // is the one failure mode scopes must not introduce.
        $scope = BlockScope::normalize($options['scope'] ?? null);

        $record = BlacklistedIp::updateOrCreate(
            // Both columns, because `(ip, scope)` is the unique index: one
            // address can hold a global block and a scoped one at once.
            //
            // `scope` has to be the '' BlockScope::normalize() returns and
            // never null. updateOrCreate builds a raw where() from these, and
            // `where('scope', null)` compiles to `scope is null`, which
            // matches nothing in a NOT NULL column — so every call would
            // insert, and collide with the row already there.
            ['ip' => $this->normalizeTarget($ip), 'scope' => $scope],
            [
                'reason'       => $options['reason'] ?? null,
                'source_env'   => $options['source_env'] ?? app()->environment(),
                'source'       => $options['source'] ?? BlockSource::Manual,
                'expires_at'   => $options['expires_at'] ?? null,
                'blocked_by'   => $options['blocked_by'] ?? null,
                'log_entry_id' => $options['log_entry_id'] ?? null,
            ]
        );

        $this->cache->write($record);

        event(new IpBlocked($record));

        // Scoped blocks stay on the node that made them. The sync payload has
        // no scope field, so the master would store this as a global block
        // and push an app-wide block to every satellite that nobody asked
        // for — a scoped block silently becoming a global one is the worst
        // thing this feature could do. `scope` joins the payload in #37,
        // which changes the wire format anyway.
        if ($record->scope === BlockScope::GLOBAL && config('watchtower.sync.master_url')) {
            PushBlockToMaster::dispatch($record)
                ->onQueue(config('watchtower.sync.queue', 'default'));
        }

        return $record;
    }

    /**
     * Apply a block that was decided on another environment.
     *
     * The one implementation of the sync write, used by both directions:
     * SyncController::receive() — a satellite reporting a block it made — and
     * watchtower:sync, pulling the master's list. Each carried its own copy
     * of the rule below, and the copies had already drifted: the pull path
     * went straight to updateOrCreate() and so never consulted never_block,
     * while config/watchtower.php promises that list covers blocks "by any
     * means — UI, auto-block, or sync" (#38).
     *
     * This is not block() because four things about a block that arrived from
     * somewhere else are decided differently:
     *
     * - never_auto_block is consulted only when the sender SAYS the block was
     *   automated, via `origin_source`. The list means "automation may not
     *   touch this, an admin still may", so applying it to every incoming
     *   record would also refuse a satellite admin's deliberate block — the
     *   one thing the list is meant to allow. A payload without the field is
     *   a node that predates it, and is treated as unknown rather than as
     *   automated: upgrading one node must never start silently refusing
     *   another's admin decisions (#56).
     * - The scope is always global. The wire format has no scope field, so
     *   there is nothing else this could write; `scope` joins it in #37.
     * - An incoming record never downgrades a local manual or auto block.
     *   That is also what makes a master whose own master_url points at
     *   itself a no-op rather than a source rewrite.
     * - Nothing is pushed onward. A block replicated from elsewhere is not
     *   this node's to report — PushBlockToMaster already drops a Sync record
     *   for that reason, so this only saves queueing a job that returns.
     *
     * log_entry_id is left out for a similar reason: it is a ULID into *this*
     * node's watchtower_logs, and the master's value names a request the
     * satellite never saw. The pull path used to copy it in, where it
     * resolved to nothing.
     *
     * @param  array{reason?: string|null, source_env?: string|null, expires_at?: mixed, blocked_by?: string|null, origin_source?: string|null}  $attributes  origin_source is what the SENDING node recorded — 'auto' is the only value that changes anything here, and null means the sender is too old to say.
     * @param  bool  $deferCache  Skip this record's cache write, for a caller that rebuilds once for a whole run. watchtower:sync pulls the entire list, and write() pays for a full rebuild on every range in it. A caller that defers owns the rebuild.
     * @param  bool  $announce  Whether to fire IpBlocked, and with it the webhook. True on the push path and false on the pull, which is what keeps a block announced once — by the environment that received it, not again by every satellite that later replicates it. That contract is documented under "Webhook Notification"; without it a satellite's first pull would post its whole inherited blocklist. **Do not announce while also deferring the cache.** The event would then say an address is blocked while the middleware, which reads only the cache, still lets it through — for however long the caller takes to rebuild. A caller that defers owns the announcement as well, once its cache is in place.
     * @return array{applied: bool, record: BlacklistedIp} applied is false when a local manual or auto block was kept, and record is that local row
     *
     * @throws NeverBlockException when the never-block whitelist covers the address
     */
    public function applySync(string $ip, array $attributes = [], bool $deferCache = false, bool $announce = true): array
    {
        // Ahead of the downgrade guard, so the answer can't depend on what
        // happens to be in the table: a never_block address is one this node
        // refuses to block, whether or not it already holds a row for it.
        $this->assertBlockable($ip);

        // Only when the sender says a rule made this. NeverAutoBlockException
        // extends NeverBlockException, so a caller that catches the parent
        // still refuses the block — it just can't tell the operator which
        // list did it. Both sync callers catch this one first for that reason.
        if (($attributes['origin_source'] ?? null) === BlockSource::Auto->value && $this->isNeverAutoBlock($ip)) {
            throw new NeverAutoBlockException(
                "{$this->normalizeIp($ip)} is in the never-auto-block list; another environment's automation cannot block it here, but an admin can."
            );
        }

        $target = $this->normalizeTarget($ip);

        // Scoped to the global row, the only row this can write. Matching any
        // row would let an unrelated LOCAL scoped block for the same address
        // — which is never a Sync block — trip the guard below and silently
        // refuse a legitimate app-wide block; and on the write it would find
        // that scoped row and turn a block on a handful of routes into an
        // app-wide one.
        // active(), because the rule protects a decision that is IN FORCE, and
        // a lapsed row is a receipt rather than a decision. Without this, a
        // local block that expired an hour ago — whose row watchtower:cleanup
        // has not swept yet — still turned away the master's live block, for
        // up to a day on a daily cleanup schedule. The master considered the
        // address blocked, this node did not block it, and the run reported
        // the disagreement as "local blocks preserved" (#74).
        //
        // find() and pick() in this same service already ignore expired rows;
        // this guard was the one place treating a dead row as a live one.
        //
        // The write below still matches on (ip, scope) without the filter, so
        // it updates that lapsed row rather than colliding with it.
        $existing = BlacklistedIp::where('ip', $target)
            ->where('scope', BlockScope::GLOBAL)
            ->active()
            ->first();

        if ($existing !== null && $existing->source !== BlockSource::Sync) {
            return ['applied' => false, 'record' => $existing];
        }

        $record = BlacklistedIp::updateOrCreate(
            ['ip' => $target, 'scope' => BlockScope::GLOBAL],
            [
                'reason'     => $attributes['reason'] ?? null,
                'source_env' => $attributes['source_env'] ?? 'unknown',
                'source'     => BlockSource::Sync,
                'expires_at' => $attributes['expires_at'] ?? null,
                'blocked_by' => $attributes['blocked_by'] ?? null,
            ]
        );

        if (! $deferCache) {
            $this->cache->write($record);
        }

        if ($announce) {
            event(new IpBlocked($record));
        }

        return ['applied' => true, 'record' => $record];
    }

    /**
     * Unblock an IP or range. Removes the DB record and rebuilds the cache.
     *
     * A single IP lifts its own row and the prefix row blocking it made, but
     * never a wider range that happens to cover it.
     *
     * Each target's entry is forgotten even when the rebuild succeeds: an
     * entry block() wrote after a failed rebuild isn't in the index, so no
     * rebuild will ever forget it.
     */
    public function unblock(string $ip, ?string $scope = null): bool
    {
        return $this->remove($ip, $scope === null ? null : [BlockScope::normalize($scope)]);
    }

    /**
     * Lift one stored block, identified by its row rather than by an address.
     *
     * The row's scope is used exactly as stored, and deliberately NOT passed
     * through BlockScope::normalize(): normalizing is a guard on *input*, and
     * a row outlives the config that declared its scope. Retire or rename a
     * scope and its rows stay in the table — normalize() then throws
     * UnknownScopeException on them, which would turn the management page's
     * Unblock into a 500 on exactly the rows an operator most needs to clear,
     * with no other way to remove them. The value came out of the database,
     * so it already matches the cache namespace it was written to.
     */
    public function unblockRecord(BlacklistedIp $record): bool
    {
        return $this->remove($record->ip, [$record->scope]);
    }

    /**
     * Delete the rows for an address in the given scopes and forget their
     * cache entries. A null $scopes means every scope.
     *
     * @param  list<string>|null  $scopes
     */
    private function remove(string $ip, ?array $scopes): bool
    {
        $targets = $this->targetsFor($ip);
        $query = BlacklistedIp::whereIn('ip', $targets);

        if ($scopes !== null) {
            $query->whereIn('scope', $scopes);
        } else {
            // No scope means every scope. "Unblock this address" has always
            // meant the address can use the app again, and it has to keep
            // meaning that: LogScope's Unblock button and
            // DELETE /api/block/{ip} both say so, and leaving a scoped block
            // behind would report the address as free while it still can't
            // reach the routes it was blocked from.
            //
            // The global scope is in the list even when no row is left for
            // it, because block() writes a cache entry directly when a
            // rebuild fails and that entry outlives the row it came from.
            $scopes = array_values(array_unique(array_merge(
                [BlockScope::GLOBAL],
                array_map('strval', (clone $query)->distinct()->pluck('scope')->all()),
            )));
        }

        $deleted = $query->delete();

        foreach ($targets as $target) {
            foreach ($scopes as $each) {
                $this->cache->forget($target, $each);
            }
        }

        $this->cache->rebuild();

        return $deleted > 0;
    }

    /**
     * The record blocking an IP or range in one scope: its own live row, else
     * whichever wider range covers it. An expired row of its own is the last
     * resort, so a lapsed block can still be reported.
     *
     * Scopes never fall back to each other. A global block already stops the
     * address everywhere, so asking whether a scope blocks it is only ever a
     * question about that scope's own rows.
     */
    public function find(string $ip, string $scope = BlockScope::GLOBAL): ?BlacklistedIp
    {
        $own = BlacklistedIp::whereIn('ip', $this->targetsFor($ip))->where('scope', $scope)->get();

        return $this->pick(
            $own,
            fn () => BlacklistedIp::active()
                ->where('scope', $scope)
                ->where('ip', 'like', '%/%')
                ->get(),
            $ip,
        );
    }

    /**
     * Choose the record blocking $ip from rows already fetched for one scope.
     *
     * $ranges is a callable because the covering-range scan reads every range
     * in the table and is only needed when the address has no live row of its
     * own. find() and status() share this so the two of them cannot drift on
     * which row wins.
     *
     * @param  Collection<int, BlacklistedIp>  $own
     * @param  callable(): Collection<int, BlacklistedIp>  $ranges
     */
    private function pick(Collection $own, callable $ranges, string $ip): ?BlacklistedIp
    {
        $live = $own->filter(fn (BlacklistedIp $row) => ! $row->isExpired());

        // An explicit /128 and the /64 around it can both be live, and the
        // query has no order, so prefer the row for this exact address.
        $record = $live->firstWhere('ip', $this->normalizeIp($ip)) ?? $live->first();

        if ($record !== null) {
            return $record;
        }

        $target = IpRange::canonical($ip);

        // Rows whose ip doesn't parse are skipped by covers().
        $covering = $target === null ? null : $ranges()
            ->first(fn (BlacklistedIp $range) => IpRange::covers([$range->ip], $target));

        return $covering ?? $own->first();
    }

    /**
     * Whether an IP or range is currently blocked, decided the way the
     * middleware decides it: never_block first, then the cache.
     *
     * A range has no single address to ask the cache about, so the row
     * blocking it answers instead. Use status() when the caller also wants
     * that row, so it isn't looked up twice.
     */
    public function isBlocked(string $ip, string $scope = BlockScope::GLOBAL): bool
    {
        return $this->decide($ip, fn () => $this->find($ip, $scope), $scope);
    }

    /**
     * What the status endpoint needs — the record blocking $ip and whether
     * it counts — from one lookup rather than find() twice.
     *
     * `blocked` means blocked app-wide, the question the global middleware
     * answers. It must not go true for a scoped block: a caller that reads
     * "blocked" and acts on it — LogScope's Unblock button is the one that
     * bit us in #16 — would be acting on an address that can still reach
     * everything except a handful of routes. Scoped blocks are reported
     * separately, under `scopes`.
     *
     * @return array{blocked: bool, record: BlacklistedIp|null, scopes: array<string, BlacklistedIp>}
     */
    public function status(string $ip): array
    {
        // Answered once up front rather than re-derived inside decide() for
        // the global record and again for every scope — it re-canonicalises
        // the address and rescans the whole never_block list each time, and
        // the answer cannot depend on the scope.
        if ($this->isNeverBlock($ip)) {
            return ['blocked' => false, 'record' => $this->find($ip), 'scopes' => []];
        }

        // Two queries whatever the scopes, the same as before they existed:
        // every row for this address, and — only if something needs it — the
        // ranges that might cover it. Resolving each scope in PHP is what
        // keeps a scope from costing a round trip.
        $own = BlacklistedIp::whereIn('ip', $this->targetsFor($ip))->get()->groupBy('scope');

        $allRanges = null;
        $rangesFor = function (string $scope) use (&$allRanges) {
            $allRanges ??= BlacklistedIp::active()
                ->where('ip', 'like', '%/%')
                ->get()
                ->groupBy('scope');

            return $allRanges->get($scope, new Collection);
        };

        $resolve = fn (string $scope) => $this->pick(
            $own->get($scope, new Collection),
            fn () => $rangesFor($scope),
            $ip,
        );

        $record = $resolve(BlockScope::GLOBAL);

        $scopes = [];

        foreach (BlockScope::declared() as $scope) {
            $scoped = $resolve($scope);

            if ($scoped !== null && $this->decide($ip, fn () => $scoped, $scope)) {
                $scopes[$scope] = $scoped;
            }
        }

        return [
            'blocked' => $this->decide($ip, fn () => $record),
            'record'  => $record,
            'scopes'  => $scopes,
        ];
    }

    /**
     * Whether $ip is blocked, asking $record only for a range — a single
     * address is answered by the cache, so the row is never fetched for it.
     *
     * @param  callable(): ?BlacklistedIp  $record
     */
    private function decide(string $ip, callable $record, string $scope = BlockScope::GLOBAL): bool
    {
        // The middleware lets these through whatever covers them, so
        // reporting them as blocked would contradict what happens. This is
        // checked for scoped blocks too: ScopedBlockMiddleware consults
        // never_block before it reads the cache, exactly as the global one
        // does.
        if ($this->isNeverBlock($ip)) {
            return false;
        }

        if (str_contains($ip, '/')) {
            $found = $record();

            return $found !== null && ! $found->isExpired();
        }

        return $this->cache->isBlocked($this->normalizeIp($ip), $scope);
    }

    /**
     * Normalize an IP address or range to its canonical form, e.g.
     * ::ffff:1.2.3.4 → 1.2.3.4, 10.1.2.3/8 → 10.0.0.0/8. Anything that
     * isn't an IP or range comes back unchanged.
     */
    public function normalizeIp(string $ip): string
    {
        return IpRange::canonical($ip) ?? $ip;
    }

    /**
     * What block() stores for $ip: normalizeIp(), with a single IPv6
     * address widened to the configured prefix.
     */
    public function normalizeTarget(string $ip): string
    {
        return IpRange::blockTarget($ip) ?? $ip;
    }

    /**
     * The rows that are this IP or range. A single IPv6 address has two: the
     * prefix block() stores, and the bare address an explicit /128, or a
     * block made before prefixes existed, left behind.
     *
     * @return list<string>
     */
    private function targetsFor(string $ip): array
    {
        return array_values(array_unique([$this->normalizeTarget($ip), $this->normalizeIp($ip)]));
    }

    /**
     * Refuse an address the never-block whitelist covers.
     *
     * Shared by block() and applySync() so the two write paths can't come to
     * different conclusions — or report the same refusal in different words,
     * since the master returns this message to the satellite that asked.
     *
     * @throws NeverBlockException
     */
    private function assertBlockable(string $ip): void
    {
        if ($this->isNeverBlock($ip)) {
            throw new NeverBlockException("{$this->normalizeIp($ip)} is in the never-block whitelist and cannot be blocked.");
        }
    }

    /**
     * Both delegate to NeverBlockList, which is also what RuleSimulator asks
     * so that a backtest and a real block agree about who is protected. The
     * two-list distinction is kept here, not folded into the helper, because
     * each throws its own exception and callers act on which one they got.
     */
    private function isNeverBlock(string $ip): bool
    {
        return NeverBlockList::neverBlock($ip);
    }

    private function isNeverAutoBlock(string $ip): bool
    {
        return NeverBlockList::neverAutoBlock($ip);
    }
}
