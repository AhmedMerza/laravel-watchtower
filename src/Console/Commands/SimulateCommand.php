<?php

declare(strict_types=1);

namespace Watchtower\Console\Commands;

use Illuminate\Console\Command;
use Illuminate\Support\Facades\Schema;
use Watchtower\Services\RuleSimulator;

/**
 * Answers "what would this rule have blocked last week" without waiting a
 * week to find out.
 *
 * `warn` mode is the honest way to arm a rule, and it costs days: you set
 * it, you wait, you read logs. Watchtower can skip the waiting because
 * LogScope already kept the history the rule would have read. No other
 * Laravel firewall package can do this, for the plain reason that none of
 * them has the data.
 *
 * READ-ONLY, and structurally so — this talks to RuleSimulator, which has no
 * path to BlacklistService and issues nothing but SELECTs. A backtest that
 * could block somebody would be a trap, since the reason to run it is that
 * you don't yet trust the rule.
 */
class SimulateCommand extends Command
{
    /** Addresses printed per rule before the table is truncated. */
    private const MAX_ROWS = 25;

    protected $signature = 'watchtower:simulate
                            {--days=7 : How far back to replay}
                            {--rule= : Replay only this rule index}
                            {--json : Emit machine-readable JSON instead of tables}';

    protected $description = 'Backtest the auto-block rules against LogScope history. Writes nothing.';

    public function __construct(private readonly RuleSimulator $simulator)
    {
        parent::__construct();
    }

    public function handle(): int
    {
        $days = $this->days();

        if ($days === null) {
            $this->error('--days must be a whole number of days, at least 1.');

            return self::FAILURE;
        }

        $table = $this->simulator->table();

        // Checked rather than left to blow up mid-report: the overwhelmingly
        // likely cause is that LogScope isn't installed, and a schema error
        // from deep in a query builder doesn't say that.
        if (! Schema::hasTable($table)) {
            $this->error("The log table `{$table}` doesn't exist, so there is no history to replay.");
            $this->line('This command reads LogScope\'s log table. Install ahmedmerza/logscope, or point');
            $this->line('`logscope.table` at wherever your log entries actually live.');

            return self::FAILURE;
        }

        /** @var array<int, array<string, mixed>> $rules */
        $rules = (array) config('watchtower.auto_block.rules', []);
        $rules = $this->selected($rules);

        if ($rules === null) {
            $this->error('--rule must be the index of a configured rule.');

            return self::FAILURE;
        }

        if ($rules === []) {
            $this->warn('No auto-block rules are configured, so there is nothing to backtest.');
            $this->line('Rules live under `auto_block.rules` in config/watchtower.php.');

            // Not a failure: an app that only runs the real-time detectors
            // has no rules by design, and a scripted caller shouldn't have
            // to treat that as an error.
            return self::SUCCESS;
        }

        $to = now();
        $from = $to->copy()->subDays($days);
        $duration = (int) config('watchtower.auto_block.block_duration_minutes', 60);
        $sharedIpThreshold = $this->sharedIpThreshold();
        $globalMode = $this->mode(config('watchtower.auto_block.mode', 'warn'));

        $results = [];

        foreach ($rules as $index => $rule) {
            $results[] = $this->simulator->simulate(
                $rule,
                (int) $index,
                $from,
                $to,
                $duration,
                $sharedIpThreshold,
                $this->mode($rule['mode'] ?? null) ?? $globalMode,
            );
        }

        if ($this->option('json')) {
            $this->line((string) json_encode([
                'from'                     => $from->toIso8601String(),
                'to'                       => $to->toIso8601String(),
                'days'                     => $days,
                'table'                    => $table,
                'block_duration_minutes'   => $duration,
                'shared_ip_user_threshold' => $sharedIpThreshold,
                'rules'                    => $results,
            ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));

            return self::SUCCESS;
        }

        $this->report($results, $from->toDateTimeString(), $to->toDateTimeString(), $days, $sharedIpThreshold);

        return self::SUCCESS;
    }

    /**
     * @param  list<array<string, mixed>>  $results
     */
    private function report(array $results, string $from, string $to, int $days, int $sharedIpThreshold): void
    {
        $this->info(sprintf(
            'Replaying %d rule(s) over %d day(s): %s → %s.',
            count($results),
            $days,
            $from,
            $to,
        ));
        $this->line('Nothing is written — this is a read-only backtest.');

        foreach ($results as $result) {
            $this->newLine();
            $this->line($this->heading($result));

            /** @var list<array<string, mixed>> $offenders */
            $offenders = $result['offenders'];

            if ($offenders === []) {
                $this->line('  Nothing would have been blocked.');

                continue;
            }

            $blocks = array_sum(array_column($offenders, 'blocks'));

            $this->line(sprintf(
                '  %d address(es) would have been blocked, %d block(s) in total.',
                count($offenders),
                $blocks,
            ));

            $this->table(
                ['IP', 'Blocks', 'First', 'Last', 'Users', 'Clean signed-in', 'Guard'],
                array_map(static fn (array $o): array => [
                    $o['ip'],
                    $o['blocks'],
                    self::minutePrecision($o['first_block_at']),
                    self::minutePrecision($o['last_block_at']),
                    $o['distinct_users'],
                    $o['authenticated_rows_not_matching'],
                    $o['held_back_by_shared_ip_guard'] ? 'held back' : '—',
                ], array_slice($offenders, 0, self::MAX_ROWS)),
            );

            if (count($offenders) > self::MAX_ROWS) {
                $this->line(sprintf(
                    '  … and %d more. Use --json for the full list.',
                    count($offenders) - self::MAX_ROWS,
                ));
            }

            $this->caveats($offenders, $sharedIpThreshold);
        }
    }

    /**
     * The two things that should stop someone arming a rule on these numbers.
     *
     * @param  list<array<string, mixed>>  $offenders
     */
    private function caveats(array $offenders, int $sharedIpThreshold): void
    {
        $falsePositives = count(array_filter(
            $offenders,
            static fn (array $o): bool => $o['authenticated_rows_not_matching'] > 0,
        ));

        if ($falsePositives > 0) {
            $this->warn(sprintf(
                '  %d of these also sent signed-in traffic that never matched the rule — a block would have taken that away too.',
                $falsePositives,
            ));
        }

        $heldBack = count(array_filter(
            $offenders,
            static fn (array $o): bool => $o['held_back_by_shared_ip_guard'],
        ));

        if ($heldBack > 0) {
            $this->warn(sprintf(
                '  %d would have been held back by the shared-IP guard (>= %d signed-in users), so they would have been warnings, not blocks.',
                $heldBack,
                $sharedIpThreshold,
            ));
        }
    }

    /**
     * `2026-09-21T10:30:09+00:00` → `2026-09-21 10:30`, for the table only.
     *
     * Seconds and offset are noise in a terminal column, and the engine's
     * real resolution is the one-minute scheduler tick anyway — printing a
     * second would claim a precision this backtest doesn't have. `--json`
     * keeps the full ISO string for anything actually parsing it.
     */
    private static function minutePrecision(string $iso): string
    {
        return str_replace('T', ' ', substr($iso, 0, 16));
    }

    /** @param  array<string, mixed>  $result */
    private function heading(array $result): string
    {
        $filters = array_filter([
            $result['level'] !== null ? "level={$result['level']}" : null,
            $result['message_contains'] !== null ? "contains='{$result['message_contains']}'" : null,
        ]);

        return sprintf(
            'Rule #%d — %s%d hit(s) in %d min [%s]%s',
            $result['rule_index'],
            $filters === [] ? 'any entry, ' : implode(', ', $filters).', ',
            $result['threshold'],
            $result['window_minutes'],
            $result['mode'],
            $result['scope'] !== null ? ", scope={$result['scope']}" : '',
        );
    }

    /**
     * `--rule=N` narrows to one rule, keeping its real index so the report
     * still names the rule the operator has to go and edit.
     *
     * @param  array<int, array<string, mixed>>  $rules
     * @return array<int, array<string, mixed>>|null null when --rule names no rule
     */
    private function selected(array $rules): ?array
    {
        $only = $this->option('rule');

        if ($only === null || $only === '') {
            return $rules;
        }

        if (! ctype_digit($only) || ! array_key_exists((int) $only, $rules)) {
            return null;
        }

        return [(int) $only => $rules[(int) $only]];
    }

    private function days(): ?int
    {
        $days = $this->option('days');

        if (! is_string($days) || ! ctype_digit($days) || (int) $days < 1) {
            return null;
        }

        return (int) $days;
    }

    /**
     * Same threshold the live guard reads, minus the warning.
     *
     * AutoBlockService logs when this is misconfigured, because there it is
     * about to decide whether someone gets blocked. Here it only labels a
     * column in a report, so a bad value quietly falls back rather than
     * shouting about it a second time.
     */
    private function sharedIpThreshold(): int
    {
        $configured = config('watchtower.auto_block.shared_ip_user_threshold', 3);

        if (is_int($configured) && $configured >= 0) {
            return $configured;
        }

        return is_string($configured) && ctype_digit(trim($configured)) ? (int) trim($configured) : 3;
    }

    /**
     * Mirrors AutoBlockService: an unrecognised mode reads as 'warn', and a
     * rule that names one is answered on its own terms rather than
     * inheriting the global one.
     */
    private function mode(mixed $mode): ?string
    {
        if ($mode === null) {
            return null;
        }

        return is_string($mode) && in_array($mode, ['block', 'warn', 'disabled'], true) ? $mode : 'warn';
    }
}
