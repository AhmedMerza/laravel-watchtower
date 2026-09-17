<?php

declare(strict_types=1);

namespace Watchtower\Exceptions;

/**
 * Thrown by BlacklistService::block() for an IP on the never-block list.
 *
 * Its own class so callers can catch this refusal without also catching a
 * failed write: QueryException and RedisException are RuntimeExceptions too.
 */
class NeverBlockException extends \RuntimeException {}
