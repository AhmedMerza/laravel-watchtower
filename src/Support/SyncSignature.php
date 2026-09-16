<?php

declare(strict_types=1);

namespace Watchtower\Support;

/**
 * The sync wire format, in one place.
 *
 * Satellites sign here; the master verifies with the same class, so the
 * canonical string can't drift between the two. Previously the format lived
 * as a hand-rolled hash_hmac() call in two clients and nowhere on the
 * receiving end at all.
 *
 * The paths are protocol constants, deliberately NOT derived from
 * watchtower.routes.prefix: the path is part of what gets signed, so a
 * satellite would have to know the master's prefix config to sign correctly.
 */
final class SyncSignature
{
    public const TIMESTAMP_HEADER = 'X-Watchtower-Timestamp';

    public const SIGNATURE_HEADER = 'X-Watchtower-Signature';

    /** Satellite → master: fetch the master's active blocklist. */
    public const PULL_PATH = '/watchtower/sync/blocks';

    /** Satellite → master: report a block made locally. */
    public const PUSH_PATH = '/watchtower/sync/block';

    /**
     * The canonical string is timestamp + METHOD + path + raw body.
     *
     * Method and path are in there as a domain separator: without them a
     * captured pull signature could be replayed against the push route.
     */
    public static function compute(string $timestamp, string $method, string $path, string $body, string $secret): string
    {
        return hash_hmac('sha256', $timestamp.$method.$path.$body, $secret);
    }

    /**
     * Signed headers for an outgoing request. The body must be the exact
     * bytes that go on the wire — send it with withBody(), not an array the
     * HTTP client re-encodes, or the two can differ.
     *
     * @return array<string, string>
     */
    public static function headers(string $method, string $path, string $body, string $secret): array
    {
        $timestamp = (string) now()->timestamp;

        return [
            self::TIMESTAMP_HEADER => $timestamp,
            self::SIGNATURE_HEADER => self::compute($timestamp, $method, $path, $body, $secret),
        ];
    }
}
