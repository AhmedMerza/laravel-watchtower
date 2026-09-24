<?php

declare(strict_types=1);

/**
 * Builds the page behind the README's watchtower:simulate image.
 *
 * Boots the package the way its test suite does (Testbench, in-memory
 * SQLite, the same minimal log_entries table), seeds a week of plausible
 * LogScope history, runs the real command, and prints its coloured output
 * as an HTML page. Only the prompt line is staged. The clock is pinned so a
 * re-render changes only when the command's output does.
 *
 * Don't run this directly — .github/demo/render.sh turns it into the PNG.
 */

require __DIR__.'/../../vendor/autoload.php';

use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use Symfony\Component\Console\Output\BufferedOutput;
use Symfony\Component\Console\Output\OutputInterface;
use Watchtower\Tests\TestCase;

final class SimulateDemo extends TestCase
{
    private const COMMAND = 'php artisan watchtower:simulate --days=7';

    public function page(): string
    {
        $this->setUp();

        Carbon::setTestNow('2026-09-24 09:30:00');

        config()->set('watchtower.auto_block.rules', [
            [
                'level'            => 'warning',
                'message_contains' => 'Failed login',
                'count'            => 20,
                'window_minutes'   => 5,
                'mode'             => 'block',
            ],
            [
                'level'            => 'error',
                'message_contains' => null,
                'count'            => 50,
                'window_minutes'   => 5,
            ],
        ]);

        $rows = [
            // A credential-stuffing run: 60 failed logins in two minutes.
            ...$this->burst('203.0.113.7', 'warning', 'Failed login for admin@example.com', 60, now()->subDays(2)->setTime(3, 12), 2),
            // An office gateway where a dozen staff mistype passwords in one
            // morning — enough to trip the rule, but the shared-IP guard sees
            // the signed-in users behind it.
            ...$this->burst('192.0.2.10', 'warning', 'Failed login for staff', 24, now()->subDays(5)->setTime(9, 1), 4, users: 12),
            // A scanner hammering routes that throw.
            ...$this->burst('198.51.100.23', 'error', 'SQLSTATE[42000]: Syntax error or access violation', 140, now()->subDays(1)->setTime(22, 40), 3),
            // Background noise that should stay under every threshold.
            ...$this->burst('198.51.100.88', 'error', 'Undefined array key "id"', 9, now()->subDays(4)->setTime(14, 5), 60),
        ];

        foreach (array_chunk($rows, 200) as $chunk) {
            DB::table('log_entries')->insert($chunk);
        }

        $output = new BufferedOutput(OutputInterface::VERBOSITY_NORMAL, decorated: true);
        Artisan::call('watchtower:simulate', ['--days' => '7'], $output);

        return str_replace(
            ['{{command}}', '{{output}}'],
            [htmlspecialchars(self::COMMAND), $this->toHtml(rtrim($output->fetch()))],
            (string) file_get_contents(__DIR__.'/terminal.html'),
        );
    }

    /**
     * @return list<array<string, mixed>>
     */
    private function burst(string $ip, string $level, string $message, int $count, DateTimeInterface $start, int $minutes, int $users = 0): array
    {
        $step = intdiv($minutes * 60, $count);

        return array_map(fn (int $i): array => [
            'id'          => (string) Str::ulid(),
            'level'       => $level,
            'message'     => $message,
            'ip_address'  => $ip,
            'user_id'     => $users > 0 ? 1 + ($i % $users) : null,
            'occurred_at' => now()->parse($start)->addSeconds($i * $step),
            'created_at'  => now()->parse($start)->addSeconds($i * $step),
            'updated_at'  => now()->parse($start)->addSeconds($i * $step),
        ], range(0, $count - 1));
    }

    /**
     * ANSI foreground colours and bold to spans. Symfony's formatter emits
     * nothing fancier than that.
     */
    private function toHtml(string $ansi): string
    {
        $html = '';
        $open = false;

        foreach (preg_split('/\e\[([\d;]*)m/', $ansi, flags: PREG_SPLIT_DELIM_CAPTURE) ?: [] as $i => $part) {
            if ($i % 2 === 0) {
                $html .= htmlspecialchars($part);

                continue;
            }

            if ($open) {
                $html .= '</span>';
                $open = false;
            }

            $classes = array_filter(array_map(fn (string $code): ?string => match (true) {
                $code === '1'                          => 'b',
                (int) $code >= 30 && (int) $code <= 37 => 'c'.((int) $code - 30),
                default                                => null,
            }, explode(';', $part)));

            if ($classes !== []) {
                $html .= '<span class="'.implode(' ', $classes).'">';
                $open = true;
            }
        }

        return $this->dimTableRules($html.($open ? '</span>' : ''));
    }

    /**
     * Greys out the table's +---+ and | so the data reads first. Colour
     * only — every character stays where the command put it.
     */
    private function dimTableRules(string $html): string
    {
        return (string) preg_replace_callback('/^(?:\+[-+]+|\|.*)$/m', fn (array $line): string => str_starts_with($line[0], '+')
            ? '<span class="rule">'.$line[0].'</span>'
            : str_replace('|', '<span class="rule">|</span>', $line[0]), $html);
    }
}

echo (new SimulateDemo('simulate-demo'))->page();
