<?php

declare(strict_types=1);

namespace Watchtower\Exceptions;

use InvalidArgumentException;

/**
 * A block was asked for in a scope `watchtower.scopes` doesn't declare.
 *
 * Deliberately not a NeverBlockException: those mean "this address is
 * protected", and callers catch them to report that the block was refused on
 * purpose. This one means the caller asked for something the app cannot
 * express, which is a configuration mistake, not a decision about an address.
 */
class UnknownScopeException extends InvalidArgumentException {}
