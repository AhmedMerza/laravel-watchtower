<?php

declare(strict_types=1);

use Watchtower\Support\IpRange;

it('writes an IP or range in its canonical form', function (string $value, string $expected) {
    expect(IpRange::canonical($value))->toBe($expected);
})->with([
    'IPv4'                      => ['203.0.113.7', '203.0.113.7'],
    'IPv4 range'                => ['203.0.113.0/24', '203.0.113.0/24'],
    'IPv4 host bits cleared'    => ['203.0.113.77/24', '203.0.113.0/24'],
    'IPv4 odd prefix'           => ['10.255.255.255/12', '10.240.0.0/12'],
    'IPv4 /32 is the bare IP'   => ['203.0.113.7/32', '203.0.113.7'],
    'IPv4 /0'                   => ['203.0.113.7/0', '0.0.0.0/0'],
    'IPv6 compressed'           => ['2001:0DB8:0000:0000:0000:0000:0000:0001', '2001:db8::1'],
    'IPv6 range'                => ['2001:db8:1:2:3:4:5:6/64', '2001:db8:1:2::/64'],
    'IPv6 odd prefix'           => ['2001:db8:ffff::/33', '2001:db8:8000::/33'],
    'IPv6 /128 is the bare IP'  => ['2001:db8::1/128', '2001:db8::1'],
    'IPv4-mapped'               => ['::ffff:203.0.113.7', '203.0.113.7'],
    'IPv4-mapped range'         => ['::ffff:203.0.113.7/120', '203.0.113.0/24'],
    'leading zeros in a prefix' => ['203.0.113.0/024', '203.0.113.0/24'],
]);

it('rejects anything that is not an IP or range', function (string $value) {
    expect(IpRange::canonical($value))->toBeNull();
})->with([
    'empty'                        => [''],
    'hostname'                     => ['localhost'],
    'empty prefix'                 => ['203.0.113.0/'],
    'IPv4 prefix too long'         => ['203.0.113.0/33'],
    'IPv6 prefix too long'         => ['2001:db8::/129'],
    'negative prefix'              => ['203.0.113.0/-1'],
    'prefix with trailing garbage' => ['10.0.0.0/1a'],
    'decimal prefix'               => ['10.0.0.0/8.5'],
    'two slashes'                  => ['10.0.0.0/8/8'],
    'padded'                       => [' 10.0.0.1'],
    'zone id'                      => ['fe80::1%eth0'],
    'mapped range outside IPv4'    => ['::ffff:203.0.113.7/90'],
]);

it('widens a single IPv6 address to the configured prefix', function (mixed $prefix, string $value, string $expected) {
    config()->set('watchtower.ipv6_block_prefix', $prefix);

    expect(IpRange::blockTarget($value))->toBe($expected);
})->with([
    'default /64'                  => [64, '2001:db8:1:2:3:4:5:6', '2001:db8:1:2::/64'],
    '/48'                          => [48, '2001:db8:1:2::1', '2001:db8:1::/48'],
    'written with a slash'         => ['/56', '2001:db8:1:2ff::1', '2001:db8:1:200::/56'],
    '128 turns widening off'       => [128, '2001:db8::1', '2001:db8::1'],
    'too broad falls back to /64'  => [8, '2001:db8:1:2::1', '2001:db8:1:2::/64'],
    'too long falls back to /64'   => [200, '2001:db8:1:2::1', '2001:db8:1:2::/64'],
    'garbage falls back to /64'    => ['abc', '2001:db8:1:2::1', '2001:db8:1:2::/64'],
    'an explicit range is kept'    => [64, '2001:db8:1:2::/80', '2001:db8:1:2::/80'],
    'an explicit /128 is kept'     => [64, '2001:db8::1/128', '2001:db8::1'],
    'IPv4 is never widened'        => [64, '203.0.113.7', '203.0.113.7'],
    'mapped IPv4 is never widened' => [64, '::ffff:203.0.113.7', '203.0.113.7'],
]);

it('flags ranges broader than IPv4 /16 or IPv6 /32', function (string $target, bool $broad) {
    expect(IpRange::isTooBroad($target))->toBe($broad);
})->with([
    ['10.0.0.0/15', true],
    ['10.0.0.0/16', false],
    ['10.0.0.1', false],
    ['2001:d00::/31', true],
    ['2001:db8::/32', false],
    ['2001:db8::1', false],
]);

it('says whether an entry contains all of a target', function (array $entries, string $target, bool $covered) {
    expect(IpRange::covers($entries, $target))->toBe($covered);
})->with([
    'exact IP'                  => [['10.0.0.1'], '10.0.0.1', true],
    'IP in a range'             => [['10.0.0.0/8'], '10.1.2.3', true],
    'range in a wider range'    => [['10.0.0.0/8'], '10.1.0.0/16', true],
    'the same range'            => [['10.0.0.0/8'], '10.0.0.0/8', true],
    'range wider than entry'    => [['10.1.0.0/16'], '10.0.0.0/8', false],
    'IP in a range, overlap'    => [['10.0.0.1'], '10.0.0.0/24', false],
    'IPv6 spelled differently'  => [['2001:DB8:0::1'], '2001:db8::1', true],
    'IPv6 in a range'           => [['2001:db8::/32'], '2001:db8:1:2::/64', true],
    'other family'              => [['0.0.0.0/0'], '2001:db8::1', false],
    'malformed entries skipped' => [['10.0.0.0/1a', 'nope', '', null, ['x'], ' 10.0.0.1 '], '10.0.0.1', true],
    'nothing matches'           => [['10.0.0.1', '192.168.0.0/16'], '10.0.0.2', false],
]);
