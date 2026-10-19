<?php

declare(strict_types=1);

namespace Watchtower\Notifications;

use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Notifications\Messages\MailMessage;
use Illuminate\Notifications\Notification;
use Illuminate\Notifications\Slack\SlackMessage;

/**
 * One alert: an address was blocked, or would have been — or an account or
 * subnet crossed an account-targeting rule (#180), which blocks nothing.
 *
 * Carries a plain array rather than the BlacklistedIp model. A queued
 * notification re-fetches its models when the job runs, and a one-minute
 * block can be expired and deleted by then — the alert would fail on the
 * very block it exists to report.
 *
 * Extend this class and point `notifications.alerts.notification` at yours to
 * add a channel (a `toTelegram()` for a `telegram` route) or reword one.
 */
class BlockAlert extends Notification implements ShouldQueue
{
    use Queueable;

    /**
     * @param  array{
     *     type: 'blocked'|'would_have_blocked'|'account_targeted',
     *     ip: string,
     *     reason: string,
     *     scope: ?string,
     *     source?: string,
     *     expires_at?: ?string,
     *     not_blocked_because?: string,
     *     context?: array<string, mixed>,
     *     url: ?string,
     * }  $alert
     */
    public function __construct(public readonly array $alert)
    {
        $this->onQueue(config('watchtower.notifications.queue', 'default'));
    }

    /**
     * Every channel the operator gave a route to. On-demand notifiables only
     * answer for the channels they were routed to, so the routes ARE the list.
     *
     * @return list<string>
     */
    public function via(object $notifiable): array
    {
        return array_keys($notifiable->routes ?? []);
    }

    public function subject(): string
    {
        $a = $this->alert;

        return match ($a['type']) {
            'blocked'          => "Watchtower blocked {$a['ip']}",
            'account_targeted' => ($a['context']['rule'] ?? null) === 'one_account'
                ? "Watchtower: account {$a['ip']} failed logins from {$a['context']['count']} addresses"
                : "Watchtower: subnet {$a['ip']} failed logins against {$a['context']['count']} accounts",
            default            => "Watchtower would have blocked {$a['ip']}",
        };
    }

    /**
     * @return list<string>
     */
    public function lines(): array
    {
        $a = $this->alert;

        if ($a['type'] === 'account_targeted') {
            return $this->accountLines($a);
        }

        $lines = ["Address: {$a['ip']}", "Reason: {$a['reason']}"];

        if (isset($a['context']['detector'])) {
            $lines[] = "Detector: {$a['context']['detector']}";
        } elseif (isset($a['context']['rule_index'])) {
            $lines[] = "Rule: auto_block.rules[{$a['context']['rule_index']}]";
        }

        $lines[] = 'Scope: '.($a['scope'] ?? 'whole app');

        if ($a['type'] === 'blocked') {
            $lines[] = 'Source: '.($a['source'] ?? 'auto');
            $lines[] = 'Expires: '.($a['expires_at'] ?? 'never');
        } else {
            $lines[] = 'Not blocked because: '.($a['not_blocked_because'] ?? 'unknown');

            // Present only in warn mode; null there means block mode would
            // have gone ahead.
            if (array_key_exists('in_block_mode', $a['context'] ?? [])) {
                $lines[] = 'In block mode: '.($a['context']['in_block_mode'] ?? 'it would have been blocked');
            }
        }

        return $lines;
    }

    /**
     * @param  array<string, mixed>  $a
     * @return list<string>
     */
    private function accountLines(array $a): array
    {
        $c = $a['context'];
        $account = $c['rule'] === 'one_account';
        $listed = implode(', ', $c['listed']).($c['unlisted'] > 0 ? " and {$c['unlisted']} more" : '');

        $lines = $account
            ? ["Account: {$a['ip']}", 'Guard: '.($a['scope'] ?? 'none')]
            : ["Subnet: {$a['ip']}"];

        $lines[] = "Reason: {$a['reason']}";
        $lines[] = $account
            ? "Rule: one_account — {$c['count']} addresses in {$c['window_minutes']} minutes"
            : "Rule: one_subnet — {$c['count']} accounts in {$c['window_minutes']} minutes";
        $lines[] = $account
            ? "Addresses: {$listed}"
            : 'Existing accounts among them: '.($listed === '' ? 'none' : $listed);
        $lines[] = 'Nothing was blocked: act on it in an AccountTargeted listener.';

        return $lines;
    }

    public function toMail(object $notifiable): MailMessage
    {
        $mail = (new MailMessage)->subject($this->subject());

        foreach ($this->lines() as $line) {
            $mail->line($line);
        }

        return $this->alert['url'] !== null
            ? $mail->action('Open Watchtower', $this->alert['url'])
            : $mail;
    }

    public function toSlack(object $notifiable): SlackMessage
    {
        $text = '*'.$this->subject()."*\n".implode("\n", $this->lines());

        if ($this->alert['url'] !== null) {
            $text .= "\n<{$this->alert['url']}|Open Watchtower>";
        }

        return (new SlackMessage)->text($text);
    }

    /**
     * @return array<string, mixed>
     */
    public function toArray(object $notifiable): array
    {
        return $this->alert;
    }
}
