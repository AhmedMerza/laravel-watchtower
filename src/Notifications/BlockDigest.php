<?php

declare(strict_types=1);

namespace Watchtower\Notifications;

use Illuminate\Notifications\Messages\MailMessage;
use Illuminate\Notifications\Notification;
use Illuminate\Notifications\Slack\SlackMessage;
use Watchtower\Listeners\SendBlockAlert;

/**
 * The daily digest: every block, near miss and account-targeting crossing
 * since the last one, grouped by address, account or subnet (#124, #180).
 *
 * Not queued, unlike BlockAlert. It is sent from the scheduler, where waiting
 * on the mailer costs nothing, and sending it in place is what lets
 * `watchtower:alert-digest` keep the day's rows when the send fails. A queued
 * job failing later would find them already deleted.
 *
 * Extend this class and point `notifications.alerts.digest.notification` at
 * yours to add a channel or reword one.
 */
class BlockDigest extends Notification
{
    /**
     * @param  array{
     *     since: string,
     *     instant: bool,
     *     totals: array{blocked: int, would_have_blocked: int, account_targeted?: int},
     *     entries: list<array{
     *         type: 'blocked'|'would_have_blocked'|'account_targeted',
     *         ip: string,
     *         scope: ?string,
     *         reason: string,
     *         not_blocked_because: ?string,
     *         events: int,
     *         held_back: int,
     *         first_at: string,
     *         last_at: string,
     *     }>,
     *     omitted: int,
     *     url: ?string,
     * }  $digest
     */
    public function __construct(public readonly array $digest) {}

    /**
     * @return list<string>
     */
    public function via(object $notifiable): array
    {
        return array_keys($notifiable->routes ?? []);
    }

    public function subject(): string
    {
        $totals = $this->digest['totals'];

        $subject = "Watchtower digest: {$totals['blocked']} blocked, {$totals['would_have_blocked']} would have been";

        return ($totals['account_targeted'] ?? 0) > 0
            ? "{$subject}, {$totals['account_targeted']} accounts or subnets targeted"
            : $subject;
    }

    /**
     * @return list<string>
     */
    public function lines(): array
    {
        $lines = ['Since '.$this->minute($this->digest['since']).'.'];

        foreach ($this->digest['entries'] as $entry) {
            // An account-targeting entry holds the account or subnet where
            // the address goes, and an account's guard where the scope goes.
            $line = match ($entry['type']) {
                'blocked'          => 'Blocked '.$entry['ip'],
                'account_targeted' => $entry['reason'] === SendBlockAlert::ONE_SUBNET_REASON
                    ? "Subnet {$entry['ip']} targeted"
                    : "Account {$entry['ip']}".($entry['scope'] !== null ? " (guard {$entry['scope']})" : '').' targeted',
                default            => 'Would have blocked '.$entry['ip'],
            };

            $line .= ($entry['events'] > 1 ? " ({$entry['events']} times)" : '')
                .' — '.$entry['reason']
                .($entry['type'] === 'account_targeted' ? '' : ' — scope: '.($entry['scope'] ?? 'whole app'));

            if ($entry['not_blocked_because'] !== null) {
                $line .= " — not blocked because: {$entry['not_blocked_because']}";
            }

            $first = $this->minute($entry['first_at']);
            $last = $this->minute($entry['last_at']);
            $line .= ' — '.($first === $last ? $first : "{$first} to {$last}");

            // Only meaningful while instant alerts are on; with them off,
            // every event would read as held back.
            if ($this->digest['instant'] && $entry['held_back'] > 0) {
                $line .= " — {$entry['held_back']} not alerted at the time (throttle or cap)";
            }

            $lines[] = $line;
        }

        if ($this->digest['omitted'] > 0) {
            $lines[] = "…and {$this->digest['omitted']} more not listed here.";
        }

        return $lines;
    }

    public function toMail(object $notifiable): MailMessage
    {
        $mail = (new MailMessage)->subject($this->subject());

        foreach ($this->lines() as $line) {
            $mail->line($line);
        }

        return $this->digest['url'] !== null
            ? $mail->action('Open Watchtower', $this->digest['url'])
            : $mail;
    }

    public function toSlack(object $notifiable): SlackMessage
    {
        $text = '*'.$this->subject()."*\n".implode("\n", $this->lines());

        if ($this->digest['url'] !== null) {
            $text .= "\n<{$this->digest['url']}|Open Watchtower>";
        }

        return (new SlackMessage)->text($text);
    }

    /**
     * @return array<string, mixed>
     */
    public function toArray(object $notifiable): array
    {
        return $this->digest;
    }

    /**
     * '2026-10-07 09:12:44' → '2026-10-07 09:12'.
     */
    private function minute(string $timestamp): string
    {
        return substr($timestamp, 0, 16);
    }
}
