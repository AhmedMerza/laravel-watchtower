<?php

declare(strict_types=1);

namespace Watchtower\Tests\Support;

use Illuminate\Cache\ArrayStore;

/**
 * An ArrayStore that records every operation performed on it.
 *
 * Cache reads fire no events — Laravel dispatches CacheHit/CacheMissed from
 * the Repository but nothing at all for the add()/increment() pair the hit
 * counter uses — so a test that wants to know what the detector path costs
 * has to sit underneath the Repository and count.
 *
 * Each entry is "{op} {key}", in the order the store saw them, so a test can
 * assert the whole sequence and read a diff when it changes rather than chase
 * a number that moved.
 *
 * ⚠️ One logged op must equal one Redis round trip, or the count means
 * nothing. That is why add() is defined here even though ArrayStore has no
 * such method: without it Repository::add() falls back to a get()+put() pair
 * and would bill two ops for what RedisStore does in a single eval.
 */
class CountingStore extends ArrayStore
{
    /** @var list<string> */
    public array $ops = [];

    /**
     * Whether a parent call is already in flight, so its internal traffic is
     * not billed on top of the operation that caused it — ArrayStore's own
     * increment() calls $this->get(), where Redis issues one INCRBY.
     */
    private bool $nested = false;

    /**
     * @param  string  $key
     */
    public function get($key): mixed
    {
        $this->log('get', $key);

        return parent::get($key);
    }

    /**
     * @param  string  $key
     * @param  mixed  $value
     * @param  int  $seconds
     */
    public function put($key, $value, $seconds): bool
    {
        $this->log('put', $key);

        return parent::put($key, $value, $seconds);
    }

    /**
     * SETNX, the way RedisStore::add() behaves — one round trip.
     *
     * parent::get()/parent::put() rather than the overrides above, so the
     * halves of a single operation are not billed separately.
     *
     * @param  string  $key
     * @param  mixed  $value
     * @param  int  $seconds
     */
    public function add($key, $value, $seconds): bool
    {
        $this->log('add', $key);

        if (parent::get($key) !== null) {
            return false;
        }

        return parent::put($key, $value, $seconds);
    }

    /**
     * @param  string  $key
     * @param  int  $value
     */
    public function increment($key, $value = 1): int|bool
    {
        $this->log('increment', $key);

        $this->nested = true;

        try {
            return parent::increment($key, $value);
        } finally {
            $this->nested = false;
        }
    }

    /**
     * @param  string  $key
     */
    public function forget($key): bool
    {
        $this->log('forget', $key);

        return parent::forget($key);
    }

    private function log(string $op, string $key): void
    {
        if ($this->nested) {
            return;
        }

        $this->ops[] = "{$op} {$key}";
    }

    /**
     * The ops recorded so far whose key contains $needle, with the configured
     * cache prefix stripped so assertions stay readable.
     *
     * @return list<string>
     */
    public function opsMatching(string $needle): array
    {
        $prefix = (string) config('watchtower.cache.key', 'watchtower:blacklist');

        return array_values(array_map(
            static fn (string $op): string => str_replace($prefix.':', '', $op),
            array_filter($this->ops, static fn (string $op): bool => str_contains($op, $needle)),
        ));
    }
}
