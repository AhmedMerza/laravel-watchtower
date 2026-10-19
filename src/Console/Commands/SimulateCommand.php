<?php

declare(strict_types=1);

namespace Watchtower\Console\Commands;

use Carbon\CarbonInterface;
use Illuminate\Console\Command;
use Illuminate\Support\Facades\Schema;
use Symfony\Component\Console\Formatter\OutputFormatter;
use Watchtower\Exceptions\UnknownScopeException;
use Watchtower\Services\AccountReplay;
use Watchtower\Services\AccountTargeting;
use Watchtower\Services\AutoBlockService;
use Watchtower\Services\DetectorHistory;
use Watchtower\Services\RuleSimulator;
use Watchtower\Services\SignalReplay;
use Watchtower\Support\BlockScope;
use Watchtower\Support\SignalLog;

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
 * The real-time detectors count signals LogScope never stored. With the
 * signal log on they are replayed from it (#177), at their own settings or
 * at --count/--window/--shared-ip-users; without it this reports what they
 * observed in warn mode instead, and says so (#123). See SignalReplay and
 * DetectorHistory.
 *
 * READ-ONLY, and structurally so — this talks to RuleSimulator,
 * SignalReplay and DetectorHistory, which have no path to BlacklistService
 * and issue nothing but SELECTs. A backtest that
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
                            {--rule= : Replay only this rule index, and skip the detectors}
                            {--detector= : Replay only this detector, and skip the rules}
                            {--count= : With --detector: replay at this many signals instead of its own count}
                            {--window= : With --detector: replay over this many minutes instead of its own window}
                            {--shared-ip-users= : With --detector: replay at this shared-IP user threshold (0 = off)}
                            {--accounts= : Replay account targeting from the signal log — both rules, or one_account / one_subnet — and skip everything else}
                            {--json : Emit machine-readable JSON instead of tables}';

    protected $description = 'Backtest the auto-block rules from LogScope history, and the detectors from the signal log. Writes nothing.';

    public function __construct(
        private readonly RuleSimulator $simulator,
        private readonly DetectorHistory $history,
        private readonly SignalReplay $replay,
        private readonly AccountReplay $accountReplay,
    ) {
        parent::__construct();
    }

    public function handle(): int
    {
        $days = $this->days();

        if ($days === null) {
            $this->error('--days must be a whole number of days, from 1 to '.self::MAX_DAYS.'.');

            return self::FAILURE;
        }

        $overrides = $this->overrides();

        if (is_string($overrides)) {
            $this->error($overrides);

            return self::FAILURE;
        }

        // Its own report: the rules and detectors judge addresses for a
        // block, account targeting judges accounts and blocks nothing.
        if ($this->input->hasParameterOption('--accounts')) {
            return $this->accounts($days, $overrides);
        }

        $to = now();
        $from = $to->copy()->subDays($days);
        $table = $this->simulator->table();
        $logScope = Schema::hasTable($table);
        $whyNotReplayed = $this->whyNotReplayed($from, $to);

        if ($overrides !== [] && $whyNotReplayed !== null) {
            $this->error("--count, --window and --shared-ip-users replay the signal log, and {$whyNotReplayed}.");

            return self::FAILURE;
        }

        // Checked rather than left to blow up mid-report: the overwhelmingly
        // likely cause is that LogScope isn't installed, and a schema error
        // from deep in a query builder doesn't say that. The signal log is
        // history enough for the detectors on its own.
        if (! $logScope && $whyNotReplayed !== null) {
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

        $detector = $this->option('detector');
        $detector = is_string($detector) && $detector !== '' ? $detector : null;

        if ($detector !== null && ($this->option('rule') ?? '') !== '') {
            $this->error('--rule and --detector each narrow the report to one thing; pick one.');

            return self::FAILURE;
        }

        if ($detector !== null && ! is_array(config("watchtower.auto_block.detectors.{$detector}"))) {
            $this->error('--detector must name a detector under auto_block.detectors.');

            return self::FAILURE;
        }

        // --detector asks about one detector; the rules would be noise
        // around it. Without LogScope there is nothing to replay them from.
        $skippedRules = ! $logScope && $rules !== [] && $detector === null;

        if ($detector !== null || ! $logScope) {
            $rules = [];
        }
        $duration = (int) config('watchtower.auto_block.block_duration_minutes', 60);
        $sharedIpThreshold = $this->sharedIpThreshold(
            config('watchtower.auto_block.shared_ip_user_threshold', AutoBlockService::DEFAULT_SHARED_IP_USER_THRESHOLD),
        );
        // `?? 'warn'` is load-bearing, not belt-and-braces. config()'s default
        // only applies when the KEY IS ABSENT, and `WATCHTOWER_AUTO_BLOCK_MODE=null`
        // in .env gives the key a literal PHP null — so config() returns null,
        // mode() passes null through, and a rule without its own mode would
        // hand null to a `string $mode` parameter under strict_types and
        // crash the command. AutoBlockService::normaliseMode() has always
        // been total for the same reason.
        $globalMode = $this->mode(config('watchtower.auto_block.mode', 'warn')) ?? 'warn';

        // --rule asks about one rule; the detectors would be noise around it.
        $detectors = $this->option('rule') === null || $this->option('rule') === ''
            ? $this->detectors($logScope ? $table : null, $from, $to, $globalMode, $whyNotReplayed === null, $detector, $overrides, $duration, $sharedIpThreshold)
            : ['detectors' => [], 'unreadable' => 0];

        if ($rules === [] && $detectors['detectors'] === [] && ! $skippedRules) {
            $this->warn('No auto-block rules or detectors are configured, so there is nothing to backtest.');
            $this->line('Rules live under `auto_block.rules` and detectors under `auto_block.detectors` in config/watchtower.php.');

            // Not a failure: a scripted caller shouldn't have to treat an
            // app with auto-block switched off as an error.
            return self::SUCCESS;
        }

        $results = [];

        foreach ($rules as $index => $rule) {
            // A rule may set its own threshold, as the live engine lets it
            // (#121). Carried on the result so the report labels each rule
            // with the number it was judged by.
            $ruleThreshold = isset($rule['shared_ip_user_threshold'])
                ? $this->sharedIpThreshold($rule['shared_ip_user_threshold'])
                : $sharedIpThreshold;

            $results[] = [
                ...$this->simulator->simulate(
                    $rule,
                    (int) $index,
                    $from,
                    $to,
                    $duration,
                    $ruleThreshold,
                    $this->mode($rule['mode'] ?? null) ?? $globalMode,
                ),
                'shared_ip_user_threshold' => $ruleThreshold,
            ];
        }

        if ($this->option('json')) {
            $this->line((string) json_encode([
                'from'                     => $from->toIso8601String(),
                'to'                       => $to->toIso8601String(),
                'days'                     => $days,
                'table'                    => $logScope ? $table : null,
                'detector_source'          => $whyNotReplayed === null ? 'signal_log' : 'logscope',
                'signal_log_oldest'        => $whyNotReplayed === null ? $this->replay->oldest()?->toIso8601String() : null,
                'rules_skipped'            => $skippedRules,
                'block_duration_minutes'   => $duration,
                'shared_ip_user_threshold' => $sharedIpThreshold,
                'rules'                    => $results,
                'detectors'                => $detectors['detectors'],
                'unreadable_detector_rows' => $detectors['unreadable'],
            ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));

            return self::SUCCESS;
        }

        if ($skippedRules) {
            $this->warn("Rules skipped: they replay LogScope's log table, and `{$table}` doesn't exist.");
        }

        if ($results !== []) {
            $this->report($results, $from->toDateTimeString(), $to->toDateTimeString(), $days, $sharedIpThreshold);
        }

        if ($detectors['detectors'] !== []) {
            $this->reportDetectors($detectors['detectors'], $detectors['unreadable'], $days, $results !== [] || $skippedRules, $whyNotReplayed, $from, $logScope);
        }

        return self::SUCCESS;
    }

    /**
     * Every detector that is enabled now, plus any that left reports in the
     * window and has since been switched off — a report about last week
     * shouldn't hide what last week's config did.
     *
     * Replayed from the signal log when $replay, else observed in LogScope.
     * Real blocks come from LogScope either way, when it is there.
     *
     * @param  ?string  $table  LogScope's table, null when it doesn't exist
     * @param  array{count?: int, window?: int, shared_ip_users?: int}  $overrides
     * @return array{detectors: array<string, array<string, mixed>>, unreadable: int}
     */
    private function detectors(
        ?string $table,
        CarbonInterface $from,
        CarbonInterface $to,
        string $globalMode,
        bool $replay,
        ?string $only,
        array $overrides,
        int $duration,
        int $globalSharedIpThreshold,
    ): array {
        $observed = $table === null
            ? ['detectors' => [], 'blocks' => [], 'unreadable' => 0]
            : $this->history->observed($table, $from, $to);

        /** @var array<string, mixed> $configured */
        $configured = (array) config('watchtower.auto_block.detectors', []);

        $names = array_keys(array_filter(
            $configured,
            static fn (mixed $settings): bool => is_array($settings) && ($settings['enabled'] ?? false),
        ));
        $names = array_values(array_unique([...$names, ...array_keys($observed['detectors']), ...array_keys($observed['blocks'])]));
        sort($names);

        if ($only !== null) {
            $names = [$only];
        }

        $detectors = [];

        foreach ($names as $name) {
            $settings = (array) ($configured[$name] ?? []);

            $mode = $this->mode($settings['mode'] ?? null) ?? $globalMode;
            $switched = $mode === 'block' && $this->switchedToWarn($name);
            $mode = $switched ? 'warn' : $mode;
            // Raw, not BlockScope::normalize(): a report must not throw
            // over a scope typo the engine already refuses loudly.
            $scope = is_scalar($settings['scope'] ?? null) ? trim((string) $settings['scope']) : BlockScope::GLOBAL;

            $detectors[$name] = [
                'enabled'          => (bool) ($settings['enabled'] ?? false),
                'mode'             => $mode,
                'switched_to_warn' => $switched,
                'scope'            => $scope,
                'offenders'        => $observed['detectors'][$name] ?? [],
                'blocks'           => $observed['blocks'][$name] ?? [],
            ];

            if (! $replay) {
                continue;
            }

            // The engine's own defaults and resolution order, so a replay
            // with no overrides is judged by what the engine would judge by.
            $judgedBy = [
                'threshold'                => $overrides['count'] ?? max(1, (int) ($settings['count'] ?? 1)),
                'window_minutes'           => $overrides['window'] ?? max(1, (int) ($settings['window_minutes'] ?? 5)),
                'shared_ip_user_threshold' => $overrides['shared_ip_users'] ?? (isset($settings['shared_ip_user_threshold'])
                    ? $this->sharedIpThreshold($settings['shared_ip_user_threshold'])
                    : $globalSharedIpThreshold),
                'overridden'               => $overrides !== [],
            ];

            // What detect() returns on before it counts anything: replaying
            // these would report decisions the engine never makes.
            $notReplayed = match (true) {
                $mode === 'disabled' => 'its mode is `disabled`, so the engine counts nothing for it',
                ! self::declared($settings['scope'] ?? null) => 'its scope isn\'t declared in watchtower.scopes, so the engine skips it',
                default => null,
            };

            if ($notReplayed !== null) {
                $detectors[$name] = [...$detectors[$name], ...$judgedBy, 'offenders' => [], 'not_replayed' => $notReplayed];

                continue;
            }

            $offenders = $this->replay->replay(
                $name,
                $judgedBy['threshold'],
                $judgedBy['window_minutes'],
                $judgedBy['shared_ip_user_threshold'],
                $mode,
                $scope,
                $duration,
                $from,
                $to,
            );

            // As DetectorHistory does for observed lines (#141): an auth
            // detector never sees a user, so who LogScope saw is the count.
            if ($table !== null && in_array($name, AutoBlockService::USERLESS_DETECTORS, true)) {
                $usersAt = DetectorHistory::usersAt($table, array_column($offenders, 'ip'), $from, $to);

                $offenders = array_map(static fn (array $o): array => [...$o, 'logscope_users' => $usersAt[$o['ip']] ?? 0], $offenders);
            }

            $detectors[$name] = [...$detectors[$name], ...$judgedBy, 'offenders' => $offenders];
        }

        return ['detectors' => $detectors, 'unreadable' => $observed['unreadable']];
    }

    /** Whether the engine would accept this scope, as resolveScope() asks. */
    private static function declared(mixed $scope): bool
    {
        try {
            BlockScope::normalize($scope);

            return true;
        } catch (UnknownScopeException) {
            return false;
        }
    }

    /**
     * --count, --window and --shared-ip-users, or the error to print.
     *
     * @return array{count?: int, window?: int, shared_ip_users?: int}|string
     */
    private function overrides(): array|string
    {
        $overrides = [];

        foreach (['count' => 1, 'window' => 1, 'shared-ip-users' => 0] as $option => $min) {
            $value = $this->option($option);

            if ($value === null || $value === '') {
                continue;
            }

            if (! is_string($value) || ! ctype_digit($value) || (int) $value < $min) {
                return $min === 0
                    ? "--{$option} must be a whole number, 0 to switch the guard off."
                    : "--{$option} must be a whole number of at least 1.";
            }

            $overrides[str_replace('-', '_', $option)] = (int) $value;
        }

        $detector = $this->option('detector');

        if ($overrides !== [] && (! is_string($detector) || $detector === '') && ! $this->input->hasParameterOption('--accounts')) {
            return '--count, --window and --shared-ip-users replay one detector; name it with --detector.';
        }

        return $overrides;
    }

    /**
     * `--accounts`: replay the account-targeting rules (#180) over the
     * signal log's failed logins. There is nothing to fall back to without
     * the log — these rules never wrote anything to observe in LogScope.
     *
     * @param  array{count?: int, window?: int, shared_ip_users?: int}  $overrides
     */
    private function accounts(int $days, array $overrides): int
    {
        $named = $this->option('accounts');
        $names = is_string($named) && $named !== '' ? [$named] : AccountTargeting::RULES;

        $error = match (true) {
            array_diff($names, AccountTargeting::RULES) !== [] => '--accounts takes one_account or one_subnet, or no value for both.',
            ($this->option('rule') ?? '') !== '' || ($this->option('detector') ?? '') !== '' => '--accounts is a report of its own; drop --rule and --detector.',
            isset($overrides['shared_ip_users']) => '--shared-ip-users is for the detectors; account targeting has no shared-IP guard.',
            $overrides !== [] && count($names) > 1 => '--count and --window replay one rule; name it, as --accounts=one_account or --accounts=one_subnet.',
            default => null,
        };

        if ($error !== null) {
            $this->error($error);

            return self::FAILURE;
        }

        $to = now();
        $from = $to->copy()->subDays($days);
        $whyNotReplayed = $this->whyNotReplayed($from, $to);

        if ($whyNotReplayed !== null) {
            $this->error("--accounts replays the signal log, and {$whyNotReplayed}.");

            return self::FAILURE;
        }

        $results = [];

        foreach ($names as $name) {
            $settings = AccountTargeting::settings($name);
            $count = $overrides['count'] ?? $settings['count'];
            $window = $overrides['window'] ?? $settings['window_minutes'];

            $results[$name] = [
                'enabled'        => AccountTargeting::enabled() && (bool) config("watchtower.auto_block.account_targeting.{$name}.enabled", false),
                'count'          => max(2, $count),
                'window_minutes' => $window,
                'ipv4_prefix'    => $name === 'one_subnet' ? $settings['ipv4_prefix'] : null,
                'overridden'     => $overrides !== [],
                'subjects'       => $this->accountReplay->replay($name, $count, $window, $settings['ipv4_prefix'], $from, $to),
            ];
        }

        if ($this->option('json')) {
            $this->line((string) json_encode([
                'from'              => $from->toIso8601String(),
                'to'                => $to->toIso8601String(),
                'days'              => $days,
                'signal_log_oldest' => $this->replay->oldest()?->toIso8601String(),
                'account_targeting' => $results,
            ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));

            return self::SUCCESS;
        }

        $this->info(sprintf('Account targeting over %d day(s) — replayed from the signal log\'s failed logins.', $days));
        $this->line('Report-only: a crossing fires AccountTargeted and blocks nothing.');

        foreach ($results as $name => $result) {
            $this->newLine();
            $this->line(sprintf(
                '<comment>%s</comment> — %d distinct %s in %d min (%s%s)',
                $name,
                $result['count'],
                $name === 'one_account' ? 'addresses per account' : sprintf('accounts per subnet (IPv4 /%d)', $result['ipv4_prefix']),
                $result['window_minutes'],
                $result['enabled'] ? 'on' : 'off',
                $result['overridden'] ? ', at --count/--window' : '',
            ));

            if ($result['subjects'] === []) {
                $this->line('  No crossings.');

                continue;
            }

            $rows = array_map(static fn (array $s): array => [
                $name === 'one_account' ? substr($s['subject'], 0, 12).'…' : $s['subject'],
                ...($name === 'one_account' ? [self::plain((string) $s['guard'])] : []),
                $s['crossings'],
                $s['members'],
                self::plain(implode(', ', array_slice($s['target_user_ids'], 0, 5)).(count($s['target_user_ids']) > 5 ? ', …' : '')),
                self::minutePrecision($s['first_at']),
                self::minutePrecision($s['last_at']),
            ], array_slice($result['subjects'], 0, self::MAX_ROWS));

            $this->table(
                $name === 'one_account'
                    ? ['Account (hash)', 'Guard', 'Crossings', 'Addresses', 'Target user ids', 'First', 'Last']
                    : ['Subnet', 'Crossings', 'Accounts', 'Target user ids', 'First', 'Last'],
                $rows,
            );

            if (count($result['subjects']) > self::MAX_ROWS) {
                $this->line(sprintf('  … and %d more. --json lists them all.', count($result['subjects']) - self::MAX_ROWS));
            }
        }

        return self::SUCCESS;
    }

    /**
     * Why the detectors can't be replayed from the signal log, or null when
     * they can (#177).
     */
    private function whyNotReplayed(CarbonInterface $from, CarbonInterface $to): ?string
    {
        return match (true) {
            ! config('watchtower.auto_block.signal_log.enabled', false) => 'the signal log is off (WATCHTOWER_SIGNAL_LOG)',
            ! Schema::hasTable(SignalLog::TABLE) => 'the signal log table `'.SignalLog::TABLE.'` doesn\'t exist — run the migrations',
            ! $this->replay->covers($from, $to) => 'the signal log holds nothing from the period',
            default => null,
        };
    }

    /**
     * Whether someone switched this detector to warn from the management
     * page (#142) — it is then writing would-have-blocked lines, not blocks,
     * and the report must say warn. An unreachable cache store reads as no.
     */
    private function switchedToWarn(string $name): bool
    {
        try {
            return app(AutoBlockService::class)->detectorMode($name)['override'] !== null;
        } catch (\Throwable) {
            return false;
        }
    }

    /**
     * @param  array<string, array<string, mixed>>  $detectors
     */
    private function reportDetectors(
        array $detectors,
        int $unreadable,
        int $days,
        bool $afterRules,
        ?string $whyNotReplayed,
        CarbonInterface $from,
        bool $logScope,
    ): void {
        if ($afterRules) {
            $this->newLine();
        }

        $replayed = $whyNotReplayed === null;

        if ($replayed) {
            $this->info(sprintf('Detectors over %d day(s) — replayed from the signal log.', $days));
            $this->line('Each crossing is one decision the detector would have made: counted the way the');
            $this->line('engine counts, held the way it holds. In block mode says what block mode would have');
            $this->line('done with it. Each detector is replayed on its own, and escalation isn\'t modelled.');

            $oldest = $this->replay->oldest();

            if ($oldest !== null && $oldest->greaterThan($from)) {
                $this->warn(sprintf(
                    'The signal log only reaches back to %s (auto_block.signal_log.retention_days), so the replay starts there.',
                    self::minutePrecision($oldest->toIso8601String()),
                ));
            }

            if (! $logScope) {
                $this->line('LogScope isn\'t installed, so real blocks and the users seen at an address aren\'t shown.');
            }
        } else {
            $this->info(sprintf('Detectors over %d day(s) — observed, not simulated.', $days));
            $this->line("They can't be replayed: {$whyNotReplayed}. This is what they reported live:");
            $this->line('one would-have-blocked line per block they were held back from, and since v0.16.0');
            $this->line('one auto-blocked line per real block. Switch the signal log on to replay them.');
        }

        // Listed anyway, as the rules are replayed anyway: the report is how
        // you decide whether to switch it on. It just can't have history.
        $engineOn = (bool) config('watchtower.auto_block.enabled', false);

        foreach ($detectors as $name => $detector) {
            $this->newLine();
            $this->line(sprintf(
                'Detector %s [%s]%s%s',
                $name,
                $detector['mode'],
                $replayed ? sprintf(
                    ' — %d in %d min, shared IP %s%s',
                    $detector['threshold'],
                    $detector['window_minutes'],
                    $detector['shared_ip_user_threshold'] === 0 ? 'off' : $detector['shared_ip_user_threshold'],
                    $detector['overridden'] ? ' (overridden)' : '',
                ) : '',
                match (true) {
                    ! $detector['enabled']        => ' — switched off now',
                    $detector['switched_to_warn'] => ' — switched to warn on the management page',
                    default                       => '',
                },
            ));

            /** @var list<array<string, mixed>> $offenders */
            $offenders = $detector['offenders'];

            $this->reportRealBlocks($detector['blocks']);

            // Nothing is counted from a blocked address, so the log goes quiet
            // where a real block stood: a replay at a higher threshold can't
            // see what the address would have done instead.
            if ($replayed && $detector['blocks'] !== []) {
                $this->line('  The log holds nothing from these addresses while they were blocked, so the replay can\'t');
                $this->line('  show what they would have done had a higher threshold let them through.');
            }

            if ($offenders === [] && $replayed) {
                $this->line(isset($detector['not_replayed']) ? "  Not replayed: {$detector['not_replayed']}." : '  No crossings.');

                continue;
            }

            if ($offenders === []) {
                $this->line('  No would-have-blocked reports.');

                if ($detector['blocks'] !== []) {
                    continue;
                }

                $this->line(match (true) {
                    ! $engineOn => '  auto_block.enabled is off, so no detector has run. Switch it on with mode `warn` to collect a history.',
                    $detector['mode'] === 'disabled' => '  Its mode is `disabled`, so it never runs. Set it to `warn` to collect a history.',
                    $detector['mode'] === 'block' => '  No real block was logged either. A block written before v0.16.0 logged no line — look in the blacklist for those.',
                    default => '  Either it never reached its threshold, or LogScope isn\'t capturing `watchtower.log_channel`.',
                });

                continue;
            }

            // The auth detectors never see a user, so their lines would read
            // 0 signed-in users for an office full of customers (#141). For
            // them the count is everyone LogScope saw signed in from there.
            $userless = in_array($name, AutoBlockService::USERLESS_DETECTORS, true);
            $users = static fn (array $o): int => $userless ? (int) ($o['logscope_users'] ?? 0) : count($o['user_ids']);

            $this->table(
                ['IP', $replayed ? 'Crossings' : 'Reports', 'First', 'Last', $userless ? 'Users seen at IP' : 'Signed-in users', 'In block mode'],
                array_map(static fn (array $o): array => [
                    $o['ip'],
                    $o['reports'],
                    self::minutePrecision($o['first_at']),
                    self::minutePrecision($o['last_at']),
                    $users($o),
                    self::outcomeCell($o['outcomes']),
                ], array_slice($offenders, 0, self::MAX_ROWS)),
            );

            if (count($offenders) > self::MAX_ROWS) {
                $this->line(sprintf(
                    '  … and %d more. Use --json for the full list.',
                    count($offenders) - self::MAX_ROWS,
                ));
            }

            if ($userless) {
                $this->line('  This detector can\'t see who is signed in — a failed login has no user — so the shared-IP guard');
                $this->line(sprintf('  never holds it back. Users seen at IP counts who LogScope saw signed in from the address over the %d day(s).', $days));
                $this->line('  Put shared addresses (an office, a mobile carrier) in never_auto_block before arming it.');
            }

            // A scoped detector's block only ever covers its scope, whether
            // the shared-IP guard narrowed it or not, so both outcomes leave
            // signed-in people the rest of the app (#151).
            if ($detector['scope'] !== BlockScope::GLOBAL) {
                $inScope = count(array_filter(
                    $offenders,
                    static fn (array $o): bool => $users($o) > 0 && (isset($o['outcomes']['blocked']) || isset($o['outcomes']['blocked_in_scope'])),
                ));

                if ($inScope > 0) {
                    $this->warn(sprintf(
                        "  %d of these had signed-in users and block mode would have blocked them on '%s' routes only — those people would have lost those routes and kept the rest of the app.",
                        $inScope,
                        $detector['scope'],
                    ));
                }
            }

            // The number that decides whether a detector is safe to arm:
            // people who were signed in, behind an address block mode would
            // have blocked app-wide.
            $customers = count(array_filter(
                $offenders,
                static fn (array $o): bool => $detector['scope'] === BlockScope::GLOBAL && $users($o) > 0 && isset($o['outcomes']['blocked']),
            ));

            if ($customers > 0) {
                $this->warn(sprintf(
                    '  %d of these had signed-in users and block mode would have blocked them app-wide — arming this detector would have locked those people out.',
                    $customers,
                ));
            }

            $scoped = count(array_filter(
                $offenders,
                static fn (array $o): bool => $detector['scope'] === BlockScope::GLOBAL && $users($o) > 0 && ! isset($o['outcomes']['blocked']) && isset($o['outcomes']['blocked_in_scope']),
            ));

            if ($scoped > 0) {
                $this->warn(sprintf(
                    '  %d more had signed-in users and would have been blocked in the detector\'s scope — those people would have kept the rest of the app.',
                    $scoped,
                ));
            }

            $unknown = count(array_filter(
                $offenders,
                static fn (array $o): bool => $users($o) > 0 && isset($o['outcomes'][DetectorHistory::NOT_RECORDED]),
            ));

            if ($unknown > 0) {
                $this->warn(sprintf(
                    '  %d of these had signed-in users, reported before v0.11.0 started recording what block mode would do — read them as possible lock-outs.',
                    $unknown,
                ));
            }
        }

        if ($unreadable > 0) {
            $this->newLine();
            $this->warn(sprintf(
                '%d would-have-blocked or auto-blocked line(s) could not be used — cut short by LogScope (a rule\'s line looks the same once cut), or not naming a configured detector — so they are not counted above.',
                $unreadable,
            ));
        }
    }

    /**
     * The blocks a detector really wrote (#154): the proof that block mode
     * acted, which near misses alone can't give.
     *
     * @param  list<array<string, mixed>>  $blocks
     */
    private function reportRealBlocks(array $blocks): void
    {
        if ($blocks === []) {
            return;
        }

        $this->line(sprintf(
            '  %d real block(s) on %d address(es):',
            array_sum(array_column($blocks, 'blocks')),
            count($blocks),
        ));

        $this->table(
            ['IP', 'Blocks', 'First', 'Last', 'Minutes', 'Scope', 'Last expires'],
            array_map(static fn (array $b): array => [
                $b['ip'],
                $b['blocks'],
                self::minutePrecision($b['first_at']),
                self::minutePrecision($b['last_at']),
                $b['minutes'],
                implode(', ', array_map(
                    static fn (string $scope): string => $scope === BlockScope::GLOBAL ? 'app-wide' : self::plain($scope),
                    $b['scopes'],
                )),
                $b['expires_at'] === null ? '?' : self::minutePrecision($b['expires_at']),
            ], array_slice($blocks, 0, self::MAX_ROWS)),
        );

        if (count($blocks) > self::MAX_ROWS) {
            $this->line(sprintf('  … and %d more. Use --json for the full list.', count($blocks) - self::MAX_ROWS));
        }
    }

    /**
     * `blocked` when every report agrees, else each outcome with its count.
     *
     * @param  array<string, int>  $outcomes
     */
    private static function outcomeCell(array $outcomes): string
    {
        arsort($outcomes);

        $cells = array_map(
            static fn (string|int $outcome, int $n): string => self::plain((string) $outcome).(count($outcomes) > 1 ? " ×{$n}" : ''),
            array_keys($outcomes),
            $outcomes,
        );

        return implode(', ', $cells);
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

            $this->caveats($offenders, $result['shared_ip_user_threshold'] ?? $sharedIpThreshold);
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

    /**
     * Text read out of a shared log table, printed as text: no control or
     * bidi characters for the terminal, no tags for Console.
     */
    private static function plain(string $text): string
    {
        return OutputFormatter::escape((string) preg_replace('/[\p{Cc}\p{Cf}]/u', '', $text));
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
    private function sharedIpThreshold(mixed $configured): int
    {
        return AutoBlockService::parseUserThreshold($configured) ?? AutoBlockService::DEFAULT_SHARED_IP_USER_THRESHOLD;
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
