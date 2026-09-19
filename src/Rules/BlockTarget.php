<?php

declare(strict_types=1);

namespace Watchtower\Rules;

use Closure;
use Illuminate\Contracts\Validation\ValidationRule;
use Watchtower\Support\IpRange;

/**
 * An IP address or CIDR range that can be blocked. Ranges broader than
 * IPv4 /16 or IPv6 /32 are refused unless $allowBroad is set.
 */
class BlockTarget implements ValidationRule
{
    public function __construct(private readonly bool $allowBroad = false) {}

    public function validate(string $attribute, mixed $value, Closure $fail): void
    {
        $target = is_string($value) ? IpRange::canonical($value) : null;

        if ($target === null) {
            $fail('The :attribute field must be an IP address or a CIDR range.');

            return;
        }

        if (! $this->allowBroad && IpRange::isTooBroad($target)) {
            $fail(sprintf(
                'The :attribute range is broader than IPv4 /%d or IPv6 /%d. Send force=true to block it anyway.',
                IpRange::MIN_IPV4_PREFIX,
                IpRange::MIN_IPV6_PREFIX,
            ));
        }
    }
}
