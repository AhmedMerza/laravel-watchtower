<?php

declare(strict_types=1);

namespace Watchtower\Models;

use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Carbon;
use Watchtower\Enums\BlockSource;

/**
 * @property string $id
 * @property string $ip
 * @property string $scope '' = global, otherwise a declared scope name
 * @property string|null $reason
 * @property string|null $source_env
 * @property BlockSource $source
 * @property Carbon|null $expires_at
 * @property string|null $blocked_by
 * @property string|null $log_entry_id
 * @property Carbon|null $created_at
 * @property Carbon|null $updated_at
 */
class BlacklistedIp extends Model
{
    use HasUlids;

    protected $table = 'blacklisted_ips';

    protected $fillable = [
        'ip',
        'scope',
        'reason',
        'source_env',
        'source',
        'expires_at',
        'blocked_by',
        'log_entry_id',
    ];

    protected $casts = [
        'expires_at' => 'datetime',
        'source'     => BlockSource::class,
    ];

    public function isExpired(): bool
    {
        return $this->expires_at !== null && $this->expires_at->isPast();
    }

    public function scopeActive(Builder $query): Builder
    {
        return $query->where(function (Builder $q) {
            $q->whereNull('expires_at')->orWhere('expires_at', '>', now());
        });
    }

    /**
     * Rows whose expiry has passed. The complement of active(), with no gap
     * between them: active() keeps `expires_at > now`, so this takes the rest.
     *
     * These exist only until `watchtower:cleanup` next runs, which is exactly
     * why the management page can list them — "it expired an hour ago" and
     * "it was never blocked" look identical once the row is gone.
     */
    public function scopeExpired(Builder $query): Builder
    {
        return $query->whereNotNull('expires_at')->where('expires_at', '<=', now());
    }

    /**
     * Newest first, with the tiebreak that makes paging safe.
     *
     * `created_at` is a second-resolution timestamp, and a sync push or an
     * auto-block burst writes several rows inside one second — so ordering on
     * it alone leaves tied rows free to swap places between the query that
     * builds page 1 and the query that builds page 2. A tied row then appears
     * on both pages, or on neither, and a client enumerating the list by
     * following `next_page_url` silently misses blocks.
     *
     * The id is a ULID: unique, and already time-ordered, so as a tiebreaker
     * it settles ties without changing the order anyone actually sees. Same
     * reasoning as `watchtower:simulate`'s keyset paging on `(occurred_at,
     * id)`, for the same reason — this table ties on a timestamp constantly.
     */
    public function scopeLatestFirst(Builder $query): Builder
    {
        return $query->orderByDesc('created_at')->orderByDesc('id');
    }

    /**
     * The management list's filters.
     *
     * Kept on the model rather than in the controller so that exposing the
     * same filters on `GET /api/blocks` later is a controller change and not
     * a second copy of these rules — the two-places-that-diverge problem
     * issue #38 is already open about.
     *
     * An unrecognised `$state` lists active blocks, because a hand-edited
     * query string shouldn't be an error page on the tool you reach for when
     * something is wrong.
     *
     * @param  string|null  $source  a BlockSource value, or null for every source
     * @param  string  $state  'active', 'expired' or 'all'
     */
    public function scopeFilter(Builder $query, ?string $source = null, string $state = 'active'): Builder
    {
        if ($source !== null) {
            $query->where('source', $source);
        }

        return match ($state) {
            'expired' => $this->scopeExpired($query),
            'all'     => $query,
            default   => $this->scopeActive($query),
        };
    }
}
