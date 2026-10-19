<?php

declare(strict_types=1);

namespace Watchtower\Events;

/**
 * A credential-stuffing pattern crossed its threshold (#180): one account
 * failing from many addresses (`one_account`), or one subnet failing against
 * many accounts (`one_subnet`).
 *
 * Watchtower blocks nothing for this and touches no account. What to do —
 * a reset prompt, a step-up, a note to support — is the app's call, made in
 * a listener for this event.
 */
class AccountTargeted
{
    /**
     * @param  string  $rule  `one_account` or `one_subnet`
     * @param  string  $subject  the account's id (`one_account`), or the
     *                           subnet in CIDR form (`one_subnet`)
     * @param  list<string>  $members  the distinct addresses that failed against
     *                                 the account, or the distinct target hashes
     *                                 the subnet failed against
     * @param  list<string>  $targetUserIds  the existing accounts among them —
     *                                       an identifier that names no account
     *                                       has none
     * @param  ?string  $guard  the guard, for `one_account` only: the same
     *                          identifier on another guard is another account
     */
    public function __construct(
        public readonly string $rule,
        public readonly string $subject,
        public readonly array $members,
        public readonly array $targetUserIds,
        public readonly ?string $guard,
        public readonly int $windowMinutes,
    ) {}
}
