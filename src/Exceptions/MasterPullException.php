<?php

declare(strict_types=1);

namespace Watchtower\Exceptions;

/**
 * The master's block list could not be read: a non-2xx response ($status
 * set) or a next_cursor that would page forever ($status null).
 *
 * Its own class so watchtower:sync can report it as a failed pull rather than
 * an unexpected exception, without also catching a failed local write.
 */
class MasterPullException extends \RuntimeException
{
    public function __construct(string $message, public readonly ?int $status = null)
    {
        parent::__construct($message);
    }
}
