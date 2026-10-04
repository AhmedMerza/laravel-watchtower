<?php

declare(strict_types=1);

use Symfony\Component\HttpFoundation\IpUtils;
use Watchtower\Support\IpRange;
use Watchtower\Support\RangeIndex;

it('finds the range an address falls in, and nothing outside every range', function () {
    $index = RangeIndex::compile(['203.0.113.0/24' => 0, '198.51.100.0/24' => 0, '2001:db8::/32' => 0]);

    expect(RangeIndex::match($index, '203.0.113.200', time()))->toBe('203.0.113.0/24')
        ->and(RangeIndex::match($index, '198.51.100.0', time()))->toBe('198.51.100.0/24')
        ->and(RangeIndex::match($index, '2001:db8:ffff::1', time()))->toBe('2001:db8::/32')
        ->and(RangeIndex::match($index, '203.0.114.0', time()))->toBeNull()
        ->and(RangeIndex::match($index, '203.0.112.255', time()))->toBeNull()
        ->and(RangeIndex::match($index, '2001:db9::1', time()))->toBeNull()
        ->and(RangeIndex::match($index, 'not an ip', time()))->toBeNull()
        ->and(RangeIndex::match([], '203.0.113.1', time()))->toBeNull();
});

it('falls back to the enclosing range when the nearest one has expired or ends too soon', function () {
    $now = time();
    $index = RangeIndex::compile([
        '10.0.0.0/8'    => 0,
        '10.1.0.0/16'   => $now - 1,   // expired
        '10.1.2.0/24'   => 0,
        '10.200.0.0/16' => 0,
    ]);

    // Last start <= the address is 10.1.2.0/24, which ends before it; its
    // parent 10.1.0.0/16 has lapsed; the /8 still holds.
    expect(RangeIndex::match($index, '10.1.9.9', $now))->toBe('10.0.0.0/8')
        ->and(RangeIndex::match($index, '10.1.2.3', $now))->toBe('10.1.2.0/24')
        ->and(RangeIndex::match($index, '10.150.0.1', $now))->toBe('10.0.0.0/8')
        ->and(RangeIndex::match($index, '11.0.0.0', $now))->toBeNull();
});

it('names the narrowest live range, so a hit is credited to the most specific block', function () {
    $index = RangeIndex::compile(['10.0.0.0/16' => 0, '10.0.0.0/8' => 0, '10.0.0.0/24' => 0]);

    expect(RangeIndex::match($index, '10.0.0.5', time()))->toBe('10.0.0.0/24')
        ->and(RangeIndex::match($index, '10.0.9.5', time()))->toBe('10.0.0.0/16')
        ->and(RangeIndex::match($index, '10.9.0.5', time()))->toBe('10.0.0.0/8');
});

it('stops matching a lapsed range on time, with no recompile', function () {
    $now = time();
    $index = RangeIndex::compile(['203.0.113.0/24' => $now + 60]);

    expect(RangeIndex::match($index, '203.0.113.1', $now))->toBe('203.0.113.0/24')
        ->and(RangeIndex::match($index, '203.0.113.1', $now + 60))->toBeNull();
});

it('decodes back to the map it was compiled from', function () {
    $ranges = ['203.0.113.0/24' => 0, '10.0.0.0/8' => 1_900_000_000, '2001:db8::1' => 0, '2001:db8::/32' => 5];

    $entries = RangeIndex::entries(RangeIndex::compile($ranges));
    ksort($entries);
    ksort($ranges);

    expect($entries)->toBe($ranges);
});

it('agrees with IpUtils on random nested and overlapping ranges', function () {
    mt_srand(21);
    $now = time();
    $ranges = [];

    foreach (range(1, 400) as $_) {
        $target = IpRange::canonical(long2ip(mt_rand(0, 0x00FFFFFF) | 0x0A000000).'/'.mt_rand(8, 32));
        $ranges[$target] = mt_rand(0, 3) === 0 ? $now + mt_rand(-100, 100) : 0;
    }

    $index = RangeIndex::compile($ranges);
    $live = array_keys(array_filter($ranges, fn ($e) => $e === 0 || $e > $now));

    foreach (range(1, 2000) as $_) {
        $ip = long2ip(mt_rand(0, 0x00FFFFFF) | 0x0A000000);
        $match = RangeIndex::match($index, $ip, $now);

        expect($match !== null)->toBe(IpUtils::checkIp($ip, $live), "lookup of {$ip}");

        if ($match !== null) {
            expect($match)->toBeIn($live)->and(IpUtils::checkIp($ip, $match))->toBeTrue();
        }
    }
});
