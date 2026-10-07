<?php

declare(strict_types=1);

namespace Watchtower\Notifications;

use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Notifications\Messages\MailMessage;
use Illuminate\Notifications\Notification;
use Illuminate\Notifications\Slack\SlackMessage;

/**
 * One alert: an address was blocked, or would have been.
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
     *     type: 'blocked'|'would_have_blocked',
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
        return $this->alert['type'] === 'blocked'
            ? "Watchtower blocked {$this->alert['ip']}"
            : "Watchtower would have blocked {$this->alert['ip']}";
    }

    /**
     * @return list<string>
     */
    public function lines(): array
    {
        $a = $this->alert;
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
