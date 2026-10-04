<?php

declare(strict_types=1);

namespace Watchtower\Support;

/**
 * The cached range list, compiled so a lookup is a binary search rather than
 * a scan (#21).
 *
 * A feed import puts thousands of ranges in the list, and the list is read on
 * every request. Checking each one with IpUtils cost ~6ms a request at 5,000
 * ranges; this costs a few microseconds.
 *
 * Each address family is one packed string of fixed-width records, sorted by
 * start address with the wider range first on a tie:
 *
 *     start (4|16 bytes) . end (4|16 bytes) . pack('NNC', expires, parent, length)
 *
 * One string per family because a string unserializes in effectively no
 * time, where an array of 5,000 entries costs ~0.4ms to rebuild on every read.
 *
 * Two CIDR ranges are either disjoint or one contains the other, never a
 * partial overlap — so every range containing an address contains the last
 * range that starts at or before it, and is that range or one of its
 * ancestors. A lookup binary-searches for that range, then walks `parent`
 * links outward (at most 32 or 128 steps) until one contains the address and
 * is still live. Each range keeps its own expiry, so a lapsed range stops
 * matching on time without anyone rebuilding the list.
 */
final class RangeIndex
{
    private const META = 9;

    /**
     * @param  array<string, int>  $ranges  canonical target => expiry timestamp, 0 = permanent
     * @return array<int, string> packed records, keyed by address width in bytes
     */
    public static function compile(array $ranges): array
    {
        $families = [];

        foreach ($ranges as $target => $expires) {
            [$address, $length] = IpRange::split((string) $target);
            $start = @inet_pton($address);

            if ($start === false) {
                continue;
            }

            $families[strlen($start)][] = [$start, $start | ~self::mask(strlen($start), $length), (int) $expires, $length];
        }

        $index = [];

        foreach ($families as $width => $records) {
            // Wider first on a tied start, so the narrower range is the one a
            // lookup lands on — and the one it names, for hit attribution.
            usort($records, fn ($a, $b) => strcmp($a[0], $b[0]) ?: $a[3] <=> $b[3]);

            // Sorted this way, a range's parent is the nearest earlier range
            // still open at its start; anything that closed before it starts
            // can't be the parent of it or of anything after it.
            $open = [];
            $packed = '';

            foreach ($records as $i => [$start, $end, $expires, $length]) {
                while ($open !== [] && strcmp($records[end($open)][1], $start) < 0) {
                    array_pop($open);
                }

                $parent = $open === [] ? 0 : end($open) + 1;
                $open[] = $i;
                $packed .= $start.$end.pack('NNC', $expires, $parent, $length);
            }

            $index[$width] = $packed;
        }

        return $index;
    }

    /**
     * The live range in $index containing $ip, in canonical form, or null.
     *
     * @param  array<int, string>  $index
     */
    public static function match(array $index, string $ip, int $now): ?string
    {
        $address = @inet_pton($ip);

        if ($address === false) {
            return null;
        }

        $width = strlen($address);
        $data = $index[$width] ?? '';
        $size = 2 * $width + self::META;

        $low = 0;
        $high = intdiv(strlen($data), $size) - 1;
        $i = -1;

        while ($low <= $high) {
            $mid = ($low + $high) >> 1;

            if (strcmp(substr($data, $mid * $size, $width), $address) <= 0) {
                $i = $mid;
                $low = $mid + 1;
            } else {
                $high = $mid - 1;
            }
        }

        while ($i >= 0) {
            $offset = $i * $size;
            ['expires' => $expires, 'parent' => $parent, 'length' => $length] = unpack('Nexpires/Nparent/Clength', $data, $offset + 2 * $width);

            if (strcmp($address, substr($data, $offset + $width, $width)) <= 0 && ($expires === 0 || $expires > $now)) {
                return self::target(substr($data, $offset, $width), $length);
            }

            $i = $parent - 1;
        }

        return null;
    }

    /**
     * Decode $index back to the map compile() took — for the rare writes
     * that change one entry and recompile.
     *
     * @param  array<int, string>  $index
     * @return array<string, int>
     */
    public static function entries(array $index): array
    {
        $ranges = [];

        foreach ($index as $width => $data) {
            $size = 2 * $width + self::META;

            foreach (str_split($data, $size) as $record) {
                ['expires' => $expires, 'length' => $length] = unpack('Nexpires/Nparent/Clength', $record, 2 * $width);
                $ranges[self::target(substr($record, 0, $width), $length)] = $expires;
            }
        }

        return $ranges;
    }

    /** Spelled as IpRange::canonical() spells it: a full-length prefix is a bare IP. */
    private static function target(string $start, int $length): string
    {
        $address = (string) inet_ntop($start);

        return $length === strlen($start) * 8 ? $address : "{$address}/{$length}";
    }

    /** A packed netmask: $length one-bits, then zeros. */
    private static function mask(int $width, int $length): string
    {
        $bytes = intdiv($length, 8);
        $mask = str_repeat("\xff", $bytes);

        if ($bytes < $width) {
            $mask .= chr((0xFF << (8 - $length % 8)) & 0xFF);
        }

        return str_pad($mask, $width, "\0");
    }
}
