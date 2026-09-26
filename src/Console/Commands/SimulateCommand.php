<?php

declare(strict_types=1);

namespace Watchtower\Console\Commands;

use Illuminate\Console\Command;
use Illuminate\Support\Facades\Schema;
use Watchtower\Services\AutoBlockService;
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

    /** Ten years. Past this, --days is a typo rather than a look-back. */
    private const MAX_DAYS = 3650;

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
            $this->error('--days must be a whole number of days, from 1 to '.self::MAX_DAYS.'.');

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
        // `?? 'warn'` is load-bearing, not belt-and-braces. config()'s default
        // only applies when the KEY IS ABSENT, and `WATCHTOWER_AUTO_BLOCK_MODE=null`
        // in .env gives the key a literal PHP null — so config() returns null,
        // mode() passes null through, and a rule without its own mode would
        // hand null to a `string $mode` parameter under strict_types and
        // crash the command. AutoBlockService::normaliseMode() has always
        // been total for the same reason.
        $globalMode = $this->mode(config('watchtower.auto_block.mode', 'warn')) ?? 'warn';

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

            // The engine skips a rule whose scope no route declares, so the
            // truthful report is that it never runs — not a list of what it
            // would have caught if it did.
            if ($result['scope_declared'] === false) {
                $this->warn(sprintf(
                    "  Scope '%s' is not declared in watchtower.scopes, so the engine skips this rule entirely. Nothing was simulated.",
                    $result['scope'],
                ));

                continue;
            }

            /** @var list<array<string, mixed>> $offenders */
            $offenders = $result['offenders'];

            /** @var list<string> $neverBlocked */
            $neverBlocked = $result['never_blocked'];

            if ($offenders === []) {
                $this->line('  Nothing would have been blocked.');
                $this->reportNeverBlocked($neverBlocked);

                continue;
            }

            // An address the guard held back at every crossing is in the list
            // for its warnings, not counted here as blocked.
            $blocked = array_filter($offenders, static fn (array $o): bool => $o['blocks'] > 0);

            $this->line(sprintf(
                '  %d address(es) would have been blocked, %d block(s) in total.',
                count($blocked),
                array_sum(array_column($offenders, 'blocks')),
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
                    self::guardCell($o),
                ], array_slice($offenders, 0, self::MAX_ROWS)),
            );

            if (count($offenders) > self::MAX_ROWS) {
                $this->line(sprintf(
                    '  … and %d more. Use --json for the full list.',
                    count($offenders) - self::MAX_ROWS,
                ));
            }

            $this->caveats($offenders, $sharedIpThreshold);
            $this->reportNeverBlocked($neverBlocked);
        }
    }

    /**
     * What the shared-IP guard would have done to this address.
     *
     * Three outcomes, not two. On a GLOBAL rule the guard holds the block
     * back and the address is only warned about — for as long as it looks
     * shared, so the same address can show blocks and hold-backs both. On a SCOPED rule it does
     * the opposite of holding back — `AutoBlockService::blockOrReport()`
     * converts the hold-back into a real block narrowed to that scope, which
     * is the entire reason scopes exist. Printing "held back" for both would
     * tell an operator their scoped rule does nothing, when it is the one
     * configuration that protects everyone else behind the gateway.
     *
     * @param  array<string, mixed>  $offender
     */
    private static function guardCell(array $offender): string
    {
        if ($offender['downgraded_to_scope'] !== null) {
            return 'scoped: '.$offender['downgraded_to_scope'];
        }

        return $offender['warnings'] > 0 ? $offender['warnings'].' held back' : '—';
    }

    /**
     * Addresses a rule matched that the allow-lists protect anyway.
     *
     * Worth its own line rather than a table row: these are not near misses,
     * they are addresses the engine refuses outright, and an operator
     * scanning the table for "who would I have blocked" should not have to
     * notice a flag to find out the answer is "not them".
     *
     * @param  list<string>  $ips
     */
    private function reportNeverBlocked(array $ips): void
    {
        if ($ips === []) {
            return;
        }

        $this->line(sprintf(
            '  %d address(es) crossed this rule but are covered by never_block / never_auto_block, so the engine would have refused to block them: %s',
            count($ips),
            implode(', ', array_slice($ips, 0, 5)).(count($ips) > 5 ? ', …' : ''),
        ));
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

        $heldBack = array_filter($offenders, static fn (array $o): bool => $o['warnings'] > 0);

        if ($heldBack !== []) {
            $this->warn(sprintf(
                '  %d would have been held back by the shared-IP guard (>= %d signed-in users): %d warning(s), one a minute while it looked shared.',
                count($heldBack),
                $sharedIpThreshold,
                array_sum(array_column($heldBack, 'warnings')),
            ));
        }

        $downgraded = count(array_filter(
            $offenders,
            static fn (array $o): bool => $o['downgraded_to_scope'] !== null,
        ));

        if ($downgraded > 0) {
            $this->line(sprintf(
                '  %d crossed the shared-IP threshold on a scoped rule, so the engine would have blocked them in scope rather than app-wide — the people behind those addresses keep the rest of the app.',
                $downgraded,
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

    /**
     * The look-back period, or null when it isn't a usable number of days.
     *
     * Capped as well as floored. Carbon does not complain about
     * `subDays(999999999)` — it returns a date in the year -2735881 — so an
     * absurd value produces a lower bound that every row is after, which
     * quietly turns the narrowing aggregate into a whole-table scan. That is
     * precisely the cost this command is built to avoid, so the ceiling is
     * part of the guarantee rather than mere input hygiene.
     */
    private function days(): ?int
    {
        $days = $this->option('days');

        if (! is_string($days) || ! ctype_digit($days)) {
            return null;
        }

        $days = (int) $days;

        return $days >= 1 && $days <= self::MAX_DAYS ? $days : null;
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
        $default = AutoBlockService::DEFAULT_SHARED_IP_USER_THRESHOLD;
        $configured = config('watchtower.auto_block.shared_ip_user_threshold', $default);

        if (is_int($configured) && $configured >= 0) {
            return $configured;
        }

        return is_string($configured) && ctype_digit(trim($configured)) ? (int) trim($configured) : $default;
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

        // AutoBlockService::VALID_MODES rather than a literal: a mode added
        // there and not here would be relabelled 'warn' in the report, which
        // is the report quietly describing an engine that no longer exists.
        return is_string($mode) && in_array($mode, AutoBlockService::VALID_MODES, true) ? $mode : 'warn';
    }
}
