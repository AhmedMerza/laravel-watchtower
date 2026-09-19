<?php

declare(strict_types=1);

namespace Watchtower\Exceptions;

/**
 * Thrown by BlacklistService::block() when automation aims at an address on
 * the never-auto-block list.
 *
 * Extends NeverBlockException so a caller that only cares "this was refused
 * on principle, not by a failed write" still catches it with one clause.
 * Catch this one first when the two deserve different logging: never_block
 * is a standing rule an operator already knows about, while this refusal is
 * a rule that fired and found real people behind the address, which is worth
 * surfacing.
 */
class NeverAutoBlockException extends NeverBlockException {}
