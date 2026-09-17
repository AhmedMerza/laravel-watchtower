<?php

declare(strict_types=1);

namespace Watchtower\Support;

use Symfony\Component\HttpFoundation\IpUtils;

/**
 * Parses and compares block targets: a single IP ("203.0.113.7") or a CIDR
 * range ("203.0.113.0/24").
 *
 * Everything that reaches IpUtils goes through canonical() first. IpUtils
 * does arithmetic on whatever follows the slash, so a config typo such as
 * "10.0.0.0/1a" raises a warning, which Laravel turns into an exception, and
 * in the middleware that would fail every request.
 */
final class IpRange
{
    /** Ranges broader than these need an explicit `force` to block. */
    public const MIN_IPV4_PREFIX = 16;

    public const MIN_IPV6_PREFIX = 32;

    private const DEFAULT_IPV6_BLOCK_PREFIX = 64;

    /**
     * The standard form of an IP or range, or null if $value is neither.
     *
     * Host bits are cleared, IPv4-mapped IPv6 unwraps to IPv4, and a
     * full-length prefix collapses to the bare IP, so each target has
     * exactly one spelling to store, key and compare.
     */
    public static function canonical(string $value): ?string
    {
        [$address, $prefix] = str_contains($value, '/') ? explode('/', $value, 2) : [$value, null];

        $packed = @inet_pton($address);

        if ($packed === false) {
            return null;
        }

        $bits = strlen($packed) * 8;

        if ($prefix === null) {
            $length = $bits;
        } elseif (ctype_digit($prefix) && (int) $prefix <= $bits) {
            $length = (int) $prefix;
        } else {
            return null;
        }

        if ($bits === 128 && str_starts_with($packed, str_repeat("\0", 10)."\xff\xff")) {
            // A mapped range shorter than /96 reaches outside IPv4.
            if ($length < 96) {
                return null;
            }

            $packed = substr($packed, 12);
            $length -= 96;
            $bits = 32;
        }

        $network = (string) inet_ntop(self::mask($packed, $length));

        return $length === $bits ? $network : "{$network}/{$length}";
    }

    /**
     * What blocking $value actually stores: its canonical form, except that
     * a single IPv6 address widens to its configured prefix, because the
     * client usually controls the whole /64. An explicit range, /128
     * included, is taken as written.
     */
    public static function blockTarget(string $value): ?string
    {
        $canonical = self::canonical($value);
        $prefix = self::ipv6BlockPrefix();

        if ($canonical === null || $prefix === 128 || str_contains($value, '/') || ! str_contains($canonical, ':')) {
            return $canonical;
        }

        return self::canonical("{$canonical}/{$prefix}");
    }

    /**
     * `watchtower.ipv6_block_prefix`, falling back to /64 when it's outside
     * 32–128, since a broader default would block far more than one client.
     */
    public static function ipv6BlockPrefix(): int
    {
        $prefix = (int) ltrim((string) config('watchtower.ipv6_block_prefix', self::DEFAULT_IPV6_BLOCK_PREFIX), '/');

        return $prefix >= self::MIN_IPV6_PREFIX && $prefix <= 128 ? $prefix : self::DEFAULT_IPV6_BLOCK_PREFIX;
    }

    /**
     * Split a canonical target into its address and prefix length. A bare
     * IP has the full length.
     *
     * @return array{string, int}
     */
    public static function split(string $canonical): array
    {
        if (str_contains($canonical, '/')) {
            [$address, $length] = explode('/', $canonical, 2);

            return [$address, (int) $length];
        }

        return [$canonical, str_contains($canonical, ':') ? 128 : 32];
    }

    public static function isTooBroad(string $canonical): bool
    {
        [$address, $length] = self::split($canonical);

        return $length < (str_contains($address, ':') ? self::MIN_IPV6_PREFIX : self::MIN_IPV4_PREFIX);
    }

    /**
     * Whether one of $entries (IPs or ranges, as an operator wrote them)
     * contains all of $canonical. Malformed entries are skipped.
     *
     * @param  array<mixed>  $entries
     */
    public static function covers(array $entries, string $canonical): bool
    {
        [$address, $length] = self::split($canonical);

        foreach ($entries as $entry) {
            $entry = is_scalar($entry) ? self::canonical(trim((string) $entry)) : null;

            if ($entry !== null && self::split($entry)[1] <= $length && IpUtils::checkIp($address, $entry)) {
                return true;
            }
        }

        return false;
    }

    /** Clear every bit of a packed address past the first $length. */
    private static function mask(string $packed, int $length): string
    {
        $bytes = intdiv($length, 8);

        if ($bytes >= strlen($packed)) {
            return $packed;
        }

        $partial = chr(ord($packed[$bytes]) & (0xFF << (8 - $length % 8)) & 0xFF);

        return str_pad(substr($packed, 0, $bytes).$partial, strlen($packed), "\0");
    }
}
