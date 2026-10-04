<?php

declare(strict_types=1);

use Illuminate\Console\Scheduling\Schedule;
use Illuminate\Database\QueryException;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Queue;
use Illuminate\Support\Facades\Route;
use Watchtower\Console\Commands\ImportFeedsCommand;
use Watchtower\Enums\BlockSource;
use Watchtower\Events\IpBlocked;
use Watchtower\Events\IpUnblocked;
use Watchtower\Jobs\PushBlockToMaster;
use Watchtower\Models\BlacklistedIp;
use Watchtower\Services\BlacklistCache;
use Watchtower\Services\BlacklistService;
use Watchtower\Support\BlockScope;

const DROP_URL = 'https://feeds.test/drop.json';
const FIREHOL_URL = 'https://feeds.test/level1.netset';

beforeEach(function () {
    // One fake, reading what each URL serves right now: a second
    // Http::fake() doesn't replace the first one's stub for a URL, so a test
    // re-importing a changed feed would keep getting the first body.
    $GLOBALS['feedResponses'] = [];
    Http::preventStrayRequests();
    Http::fake(fn ($request) => Http::response(...($GLOBALS['feedResponses'][$request->url()] ?? ['', 404])));

    config()->set('watchtower.feeds', [
        'drop'    => ['enabled' => true, 'urls' => [DROP_URL]],
        'firehol' => ['enabled' => true, 'urls' => [FIREHOL_URL]],
    ]);
});

/** Spamhaus' format: one JSON object per line, then a metadata line. */
function dropFeed(array $cidrs): string
{
    return collect($cidrs)->map(fn ($cidr) => json_encode(['cidr' => $cidr, 'sblid' => 'SBL1', 'rir' => 'apnic']))
        ->push(json_encode(['type' => 'metadata', 'timestamp' => 1791060242, 'records' => count($cidrs)]))
        ->implode("\n");
}

/** FireHOL's format: a comment header, then one entry per line. */
function fireholFeed(array $entries): string
{
    return "#\n# firehol_level1\n#\n".implode("\n", $entries)."\n";
}

function fakeFeeds(array $drop, array $firehol): void
{
    serveFeeds([dropFeed($drop), 200], [fireholFeed($firehol), 200]);
}

/** @param  array{string, int}  $drop  body and status */
function serveFeeds(array $drop, array $firehol): void
{
    $GLOBALS['feedResponses'] = [DROP_URL => $drop, FIREHOL_URL => $firehol];
}

function feedIps(): array
{
    return BlacklistedIp::where('source', BlockSource::Feed)->orderBy('ip')->pluck('ip')->all();
}

it('imports every enabled feed as feed blocks the cache enforces', function () {
    fakeFeeds(['1.10.16.0/20', '2a06:e480::/29'], ['31.13.0.0/16', '45.9.20.5']);

    $this->artisan('watchtower:import-feeds')->assertSuccessful()
        ->expectsOutputToContain('4 added, 0 removed');

    expect(feedIps())->toBe(['1.10.16.0/20', '2a06:e480::/29', '31.13.0.0/16', '45.9.20.5'])
        ->and(BlacklistedIp::where('ip', '1.10.16.0/20')->value('blocked_by'))->toBe('feed:drop')
        ->and(BlacklistedIp::where('ip', '31.13.0.0/16')->value('blocked_by'))->toBe('feed:firehol');

    $cache = app(BlacklistCache::class);
    expect($cache->isBlocked('1.10.20.1'))->toBeTrue()
        ->and($cache->isBlocked('2a06:e487::1'))->toBeTrue()
        ->and($cache->isBlocked('45.9.20.5'))->toBeTrue()
        ->and($cache->isBlocked('1.10.32.1'))->toBeFalse();
});

it('removes entries a re-import no longer lists', function () {
    fakeFeeds(['1.10.16.0/20', '5.8.0.0/16'], ['31.13.0.0/16']);
    $this->artisan('watchtower:import-feeds')->assertSuccessful();

    fakeFeeds(['1.10.16.0/20', '5.9.0.0/16'], ['31.13.0.0/16']);
    $this->artisan('watchtower:import-feeds')->assertSuccessful()
        ->expectsOutputToContain('1 added, 1 removed');

    expect(feedIps())->toBe(['1.10.16.0/20', '31.13.0.0/16', '5.9.0.0/16'])
        ->and(app(BlacklistCache::class)->isBlocked('5.8.0.1'))->toBeFalse();
});

it('keeps a range one feed dropped while another still lists it', function () {
    // FireHOL level1 carries most of DROP, so this is the common case, not
    // an edge: per-feed replacement would unblock it until the next run.
    fakeFeeds(['1.10.16.0/20', '5.8.0.0/16'], ['1.10.16.0/20']);
    $this->artisan('watchtower:import-feeds')->assertSuccessful();

    fakeFeeds(['5.8.0.0/16'], ['1.10.16.0/20']);
    $this->artisan('watchtower:import-feeds')->assertSuccessful();

    expect(feedIps())->toContain('1.10.16.0/20');
});

it('never imports a private, reserved or implausibly wide range, even when a feed lists it', function () {
    fakeFeeds(
        ['1.10.16.0/20', 'fc00::/7', 'fe80::/10', '2001:db8::/32', '2000::/3'],
        ['0.0.0.0/8', '10.0.0.0/8', '100.64.0.0/10', '127.0.0.0/8', '169.254.0.0/16', '172.16.0.0/12',
            '192.168.0.0/16', '224.0.0.0/3', '192.168.4.0/24', '32.0.0.0/3', '31.13.0.0/16'],
    );

    $this->artisan('watchtower:import-feeds')->assertSuccessful();

    expect(feedIps())->toBe(['1.10.16.0/20', '31.13.0.0/16'])
        ->and(app(BlacklistCache::class)->isBlocked('192.168.1.10'))->toBeFalse()
        ->and(app(BlacklistCache::class)->isBlocked('10.0.0.5'))->toBeFalse();
});

it('leaves manual, auto and sync blocks untouched', function () {
    $manual = BlacklistedIp::create(['ip' => '1.10.16.0/20', 'source' => BlockSource::Manual, 'reason' => 'mine']);
    $auto = BlacklistedIp::create(['ip' => '45.9.20.5', 'source' => BlockSource::Auto, 'expires_at' => now()->addDay()]);
    $sync = BlacklistedIp::create(['ip' => '8.8.4.0/24', 'source' => BlockSource::Sync]);

    fakeFeeds(['1.10.16.0/20'], ['45.9.20.5', '31.13.0.0/16']);
    $this->artisan('watchtower:import-feeds')->assertSuccessful();

    fakeFeeds(['5.8.0.0/16'], ['31.13.0.0/16']);
    $this->artisan('watchtower:import-feeds')->assertSuccessful();

    expect($manual->fresh()->source)->toBe(BlockSource::Manual)
        ->and($manual->fresh()->reason)->toBe('mine')
        ->and($auto->fresh()?->source)->toBe(BlockSource::Auto)
        ->and($sync->fresh()?->source)->toBe(BlockSource::Sync)
        ->and(feedIps())->toBe(['31.13.0.0/16', '5.8.0.0/16']);
});

it('removes nothing when a feed fails to download, and fails the run so cron sees it', function () {
    fakeFeeds(['1.10.16.0/20'], ['31.13.0.0/16']);
    $this->artisan('watchtower:import-feeds')->assertSuccessful();

    serveFeeds(['', 503], [fireholFeed(['45.9.20.5']), 200]);

    $this->artisan('watchtower:import-feeds')->assertFailed()
        ->expectsOutputToContain('Feed [drop] skipped');

    // The healthy feed's addition still lands; nothing is removed — not even
    // 31.13.0.0/16, which firehol really did drop.
    expect(feedIps())->toBe(['1.10.16.0/20', '31.13.0.0/16', '45.9.20.5']);
});

it('removes nothing when a feed comes back empty or less than half its size', function (string $body) {
    fakeFeeds(['1.10.16.0/20', '5.8.0.0/16', '5.9.0.0/16', '5.10.0.0/16'], ['31.13.0.0/16']);
    $this->artisan('watchtower:import-feeds')->assertSuccessful();

    serveFeeds([$body, 200], [fireholFeed(['31.13.0.0/16']), 200]);

    $this->artisan('watchtower:import-feeds')->assertFailed();

    expect(feedIps())->toHaveCount(5);
})->with([
    'empty'         => [''],
    'an error page' => ['<html><body>Service Unavailable</body></html>'],
    'shrunk'        => [dropFeed(['1.10.16.0/20'])],
]);

it('removes a feed\'s entries once it is turned off', function () {
    fakeFeeds(['1.10.16.0/20'], ['31.13.0.0/16']);
    $this->artisan('watchtower:import-feeds')->assertSuccessful();

    config()->set('watchtower.feeds.drop.enabled', false);
    $this->artisan('watchtower:import-feeds')->assertSuccessful();

    expect(feedIps())->toBe(['31.13.0.0/16']);
});

it('announces nothing and pushes nothing anywhere', function () {
    Event::fake([IpBlocked::class]);
    fakeFeeds(['1.10.16.0/20'], ['31.13.0.0/16']);

    $this->artisan('watchtower:import-feeds')->assertSuccessful();

    Event::assertNotDispatched(IpBlocked::class);
});

it('leaves feed blocks out of reconcile', function () {
    Queue::fake();
    config()->set('watchtower.sync.master_url', 'https://master.example.com');

    BlacklistedIp::create(['ip' => '1.2.3.4', 'source' => BlockSource::Manual]);
    BlacklistedIp::create(['ip' => '1.10.16.0/20', 'source' => BlockSource::Feed, 'blocked_by' => 'feed:drop']);

    $this->artisan('watchtower:reconcile')->assertSuccessful();

    Queue::assertPushed(PushBlockToMaster::class, 1);
    Queue::assertPushed(PushBlockToMaster::class, fn ($job) => $job->record->ip === '1.2.3.4');
});

it('lets never_block win over a feed range on every request', function () {
    Route::get('/watchtower-test', fn () => 'ok');
    config()->set('watchtower.never_block', ['31.13.24.7']);

    fakeFeeds(['1.10.16.0/20'], ['31.13.0.0/16']);
    $this->artisan('watchtower:import-feeds')->assertSuccessful();

    $this->withServerVariables(['REMOTE_ADDR' => '31.13.24.7'])->get('/watchtower-test')->assertOk();
    $this->withServerVariables(['REMOTE_ADDR' => '31.13.24.8'])->get('/watchtower-test')->assertForbidden();
});

it('keeps a lookup from a non-blocked address fast with 5,000 feed ranges loaded', function () {
    // Serialized like Redis or the file store would, so the per-request
    // read of the range list is part of what's timed.
    config()->set('cache.stores.array.serialize', true);

    mt_srand(21);
    $rows = [];

    while (count($rows) < 5000) {
        $ip = sprintf('%d.%d.%d.0/24', mt_rand(11, 99), mt_rand(0, 255), mt_rand(0, 255));
        $rows[$ip] = ['id' => (string) str()->ulid(), 'ip' => $ip, 'scope' => BlockScope::GLOBAL, 'source' => 'feed'];
    }

    foreach (array_chunk(array_values($rows), 500) as $chunk) {
        BlacklistedIp::insert($chunk);
    }

    $cache = app(BlacklistCache::class);
    $cache->rebuild();

    $lookups = 500;

    // Drawn from the same space as the ranges, so lookups land between
    // them and walk parents rather than all falling below the first one.
    $probes = [];

    while (count($probes) < $lookups) {
        $probe = sprintf('%d.%d.%d.9', mt_rand(11, 99), mt_rand(0, 255), mt_rand(0, 255));

        if (! isset($rows[preg_replace('/\.9$/', '.0/24', $probe)])) {
            $probes[] = $probe;
        }
    }

    $start = hrtime(true);

    foreach ($probes as $probe) {
        $cache->isBlocked($probe);
    }

    $perLookupMs = (hrtime(true) - $start) / 1e6 / $lookups;

    // The linear IpUtils scan this replaced took ~6ms here. The budget is
    // loose for slow CI runners and still an order of magnitude below that.
    expect($perLookupMs)->toBeLessThan(0.5)
        ->and($cache->isBlocked(str_replace('.0/24', '.77', (string) array_key_first($rows))))->toBeTrue();
});

it('reads both Spamhaus JSON lines and a plain netset, skipping comments and metadata', function () {
    $body = implode("\n", [
        '; Spamhaus DROP',
        '{"cidr":"1.10.16.0/20","sblid":"SBL256894","rir":"apnic"}',
        '{"cidr":"2a06:e480::\\/29","sblid":"SBL301771","rir":"ripencc"}',
        '{"type":"metadata","timestamp":1791060242,"size":103249,"records":1692}',
        '# a comment 9.9.9.9',
        '31.13.0.77/16',
        '45.9.20.5',
        '',
        'not an address',
    ]);

    expect(ImportFeedsCommand::parse($body))->toBe(['1.10.16.0/20', '2a06:e480::/29', '31.13.0.0/16', '45.9.20.5']);
});

it('refuses a feed that covers far more address space than any real blocklist', function () {
    fakeFeeds(['1.10.16.0/20'], ['31.13.0.0/16']);
    $this->artisan('watchtower:import-feeds')->assertSuccessful();

    // 37 /10s from 4.0.0.0 (10.0.0.0/8's four are reserved): each within the
    // width floor, together ~3.6% of IPv4 — over the cap's ~3.1%.
    $wide = array_map(fn ($i) => long2ip(($i + 16) << 22).'/10', range(0, 40));
    $wide = array_values(array_filter($wide, fn ($r) => ! str_starts_with($r, '10.')));
    fakeFeeds(['1.10.16.0/20'], array_merge(['31.13.0.0/16'], $wide));

    $this->artisan('watchtower:import-feeds')->assertFailed()
        ->expectsOutputToContain('far more than any real blocklist');

    expect(feedIps())->toBe(['1.10.16.0/20', '31.13.0.0/16']);
});

it('drops a single entry wider than an IPv4 /10 or IPv6 /24', function () {
    fakeFeeds(['1.10.16.0/20', '2a00::/23', '2a06:e480::/29'], ['32.0.0.0/9', '64.0.0.0/10']);

    $this->artisan('watchtower:import-feeds')->assertSuccessful();

    expect(feedIps())->toBe(['1.10.16.0/20', '2a06:e480::/29', '64.0.0.0/10']);
});

it('reads a feed only over https', function () {
    config()->set('watchtower.feeds.drop.urls', ['http://feeds.test/drop.json']);
    fakeFeeds(['1.10.16.0/20'], ['31.13.0.0/16']);

    $this->artisan('watchtower:import-feeds')->assertFailed()
        ->expectsOutputToContain('is not an https URL');

    expect(feedIps())->toBe(['31.13.0.0/16']);
});

it('guards a feed against shrinking by its own size, not the rows another feed left it', function () {
    // FireHOL lists DROP's ranges too, so it OWNS only the one DROP lacks.
    $shared = ['5.8.0.0/16', '5.9.0.0/16', '5.10.0.0/16', '5.11.0.0/16'];
    fakeFeeds($shared, array_merge($shared, ['31.13.0.0/16']));
    $this->artisan('watchtower:import-feeds')->assertSuccessful();

    // A truncated FireHOL: 2 of its 5. Against its 1 owned row that passes.
    fakeFeeds($shared, ['5.8.0.0/16', '45.9.20.0/24']);

    $this->artisan('watchtower:import-feeds')->assertFailed()
        ->expectsOutputToContain('down from 5');

    expect(feedIps())->toContain('31.13.0.0/16');
});

it('removes every feed entry once every feed is turned off', function () {
    fakeFeeds(['1.10.16.0/20'], ['31.13.0.0/16']);
    $this->artisan('watchtower:import-feeds')->assertSuccessful();

    config()->set('watchtower.feeds.drop.enabled', false);
    config()->set('watchtower.feeds.firehol.enabled', false);

    $this->artisan('watchtower:import-feeds')->assertSuccessful();

    expect(feedIps())->toBe([])
        ->and(app(BlacklistCache::class)->isBlocked('1.10.16.1'))->toBeFalse();
});

it('removes nothing when one feed is turned off while the other fails', function () {
    fakeFeeds(['1.10.16.0/20'], ['31.13.0.0/16']);
    $this->artisan('watchtower:import-feeds')->assertSuccessful();

    config()->set('watchtower.feeds.drop.enabled', false);
    serveFeeds(['', 200], ['', 503]);

    $this->artisan('watchtower:import-feeds')->assertFailed();

    expect(feedIps())->toBe(['1.10.16.0/20', '31.13.0.0/16']);
});

it('schedules the import daily', function () {
    $event = collect(app(Schedule::class)->events())
        ->first(fn ($event) => $event->description === 'watchtower:import-feeds');

    expect($event)->not->toBeNull()
        ->and($event->expression)->toBe('0 0 * * *');
});

it('lets a manual block take over a feed row, and keeps it through the next import', function () {
    fakeFeeds(['1.10.16.0/20'], ['31.13.0.0/16']);
    $this->artisan('watchtower:import-feeds')->assertSuccessful();

    app(BlacklistService::class)->block('1.10.16.0/20', ['reason' => 'mine', 'force' => true]);

    fakeFeeds(['5.8.0.0/16'], ['31.13.0.0/16']);
    $this->artisan('watchtower:import-feeds')->assertSuccessful();

    expect(BlacklistedIp::where('ip', '1.10.16.0/20')->first()?->source)->toBe(BlockSource::Manual);
});

it('lets the master\'s block replace a feed row, so the feed dropping it later changes nothing', function () {
    fakeFeeds(['1.10.16.0/20'], ['31.13.0.0/16']);
    $this->artisan('watchtower:import-feeds')->assertSuccessful();

    $result = app(BlacklistService::class)->applySync('1.10.16.0/20', ['source_env' => 'production']);

    fakeFeeds(['5.8.0.0/16'], ['31.13.0.0/16']);
    $this->artisan('watchtower:import-feeds')->assertSuccessful();

    expect($result['applied'])->toBeTrue()
        ->and(BlacklistedIp::where('ip', '1.10.16.0/20')->first()?->source)->toBe(BlockSource::Sync)
        ->and(app(BlacklistCache::class)->isBlocked('1.10.16.1'))->toBeTrue();
});

it('brings a feed entry back on the next import after it is unblocked by hand', function () {
    fakeFeeds(['1.10.16.0/20'], ['31.13.0.0/16']);
    $this->artisan('watchtower:import-feeds')->assertSuccessful();

    app(BlacklistService::class)->unblock('1.10.16.0/20');
    expect(app(BlacklistCache::class)->isBlocked('1.10.16.1'))->toBeFalse();

    $this->artisan('watchtower:import-feeds')->assertSuccessful();
    expect(app(BlacklistCache::class)->isBlocked('1.10.16.1'))->toBeTrue();
});

it('finds the range covering an address without loading every other range', function () {
    $rows = [];

    foreach (range(0, 1999) as $i) {
        $ip = long2ip(0x0B000000 + ($i << 8)).'/24';
        $rows[] = ['id' => (string) str()->ulid(), 'ip' => $ip, 'scope' => BlockScope::GLOBAL, 'source' => 'feed'];
    }

    BlacklistedIp::insert($rows);
    // Warm, so the count below is the lookup's own reads, not a rebuild's.
    app(BlacklistCache::class)->rebuild();
    $loaded = 0;
    Event::listen('eloquent.retrieved: '.BlacklistedIp::class, function () use (&$loaded) {
        $loaded++;
    });

    $status = app(BlacklistService::class)->status('11.0.7.9');

    expect($status['record']?->ip)->toBe('11.0.7.0/24')
        ->and(app(BlacklistService::class)->find('11.0.9.1')?->ip)->toBe('11.0.9.0/24')
        ->and($loaded)->toBeLessThan(10);
});

it('imports a range over a lapsed block that cleanup has not swept yet, lifting it at the edge as cleanup would', function () {
    config()->set('watchtower.scopes', ['auth']);
    Event::fake([IpUnblocked::class]);
    BlacklistedIp::create(['ip' => '1.10.16.0/20', 'source' => BlockSource::Manual, 'expires_at' => now()->subHour()]);
    $scoped = BlacklistedIp::create(['ip' => '1.10.16.0/20', 'scope' => 'auth', 'source' => BlockSource::Manual, 'expires_at' => now()->subHour()]);
    fakeFeeds(['1.10.16.0/20'], ['31.13.0.0/16']);

    $this->artisan('watchtower:import-feeds')->assertSuccessful();

    expect(feedIps())->toBe(['1.10.16.0/20', '31.13.0.0/16'])
        ->and(app(BlacklistCache::class)->isBlocked('1.10.16.1'))->toBeTrue()
        ->and($scoped->fresh())->not->toBeNull();

    // A target pushed the lapsed temporary block only lifts it on this.
    Event::assertDispatched(IpUnblocked::class, fn ($event) => $event->ip === '1.10.16.0/20');
});

it('keeps a block that lands mid-import instead of rolling the import back', function () {
    fakeFeeds(['1.10.16.0/20', '5.8.0.0/16'], ['31.13.0.0/16']);

    // Stands in for a manual block written between the existing-row read and
    // the insert: it lands right after that read.
    $raced = false;
    DB::listen(function ($query) use (&$raced) {
        if (! $raced && str_starts_with($query->sql, 'select "source", "ip" from "blacklisted_ips"')) {
            $raced = true;
            DB::table('blacklisted_ips')->insert(['id' => (string) str()->ulid(), 'ip' => '5.8.0.0/16', 'scope' => '', 'source' => 'manual']);
        }
    });

    $this->artisan('watchtower:import-feeds')->assertSuccessful()
        ->expectsOutputToContain('2 added');

    expect(BlacklistedIp::where('ip', '5.8.0.0/16')->value('source'))->toBe(BlockSource::Manual)
        ->and(feedIps())->toBe(['1.10.16.0/20', '31.13.0.0/16']);
});

it('fails loudly rather than storing broken rows when the feed migration has not run', function () {
    // The pre-#21 source enum, as an app that upgraded the package but didn't
    // migrate still has. INSERT IGNORE / OR IGNORE would swallow this.
    (include __DIR__.'/../../database/migrations/update_blacklisted_ips_table_source_feed.php')->down();
    fakeFeeds(['1.10.16.0/20'], ['31.13.0.0/16']);

    expect(fn () => $this->artisan('watchtower:import-feeds')->run())->toThrow(QueryException::class);
    expect(BlacklistedIp::count())->toBe(0);
});

it('refuses a feed listing more entries than any real blocklist', function () {
    $singles = array_map(fn ($i) => long2ip(0x0B000000 + $i), range(1, 100_001));
    fakeFeeds(['1.10.16.0/20'], $singles);

    $this->artisan('watchtower:import-feeds')->assertFailed()
        ->expectsOutputToContain('more than the 100000');

    expect(feedIps())->toBe(['1.10.16.0/20']);
});

it('remembers a feed\'s size only when the import accepted it', function () {
    $five = ['5.8.0.0/16', '5.9.0.0/16', '5.10.0.0/16', '5.11.0.0/16', '5.12.0.0/16'];
    fakeFeeds($five, ['31.13.0.0/16']);
    $this->artisan('watchtower:import-feeds')->assertSuccessful();

    fakeFeeds(['5.8.0.0/16'], ['31.13.0.0/16']);
    $this->artisan('watchtower:import-feeds')->assertFailed();
    $this->artisan('watchtower:import-feeds')->assertFailed()
        ->expectsOutputToContain('down from 5');

    expect(Cache::get('watchtower:blacklist:feeds:drop:listed'))->toBe(5);
});

it('accepts a shrunk feed with --force, and forgets the size of a feed turned off', function () {
    $five = ['5.8.0.0/16', '5.9.0.0/16', '5.10.0.0/16', '5.11.0.0/16', '5.12.0.0/16'];
    fakeFeeds($five, ['31.13.0.0/16']);
    $this->artisan('watchtower:import-feeds')->assertSuccessful();

    fakeFeeds(['5.8.0.0/16'], ['31.13.0.0/16']);
    $this->artisan('watchtower:import-feeds', ['--force' => true])->assertSuccessful();
    expect(feedIps())->toBe(['31.13.0.0/16', '5.8.0.0/16']);

    config()->set('watchtower.feeds.firehol.enabled', false);
    $this->artisan('watchtower:import-feeds')->assertSuccessful();
    expect(Cache::has('watchtower:blacklist:feeds:firehol:listed'))->toBeFalse();
});

it('refuses a redirect from https down to plain http', function () {
    // The plain-http copy is a valid feed: only the redirect rule keeps it out.
    $GLOBALS['feedResponses'] = [
        DROP_URL                       => ['', 302, ['Location' => 'http://feeds.test/drop.json']],
        'http://feeds.test/drop.json'  => [dropFeed(['1.10.16.0/20']), 200],
        FIREHOL_URL                    => [fireholFeed(['31.13.0.0/16']), 200],
    ];

    $this->artisan('watchtower:import-feeds')->assertFailed()
        ->expectsOutputToContain('Feed [drop] skipped');

    expect(feedIps())->toBe(['31.13.0.0/16']);
});

it('reads an https URL whatever the case of its scheme', function () {
    config()->set('watchtower.feeds.drop.urls', ['HTTPS://feeds.test/drop.json']);
    fakeFeeds(['1.10.16.0/20'], ['31.13.0.0/16']);

    $this->artisan('watchtower:import-feeds')->assertSuccessful();

    expect(feedIps())->toBe(['1.10.16.0/20', '31.13.0.0/16']);
});

it('finds the covering range for an IPv4-mapped address', function () {
    BlacklistedIp::create(['ip' => '11.0.7.0/24', 'source' => BlockSource::Feed]);

    expect(app(BlacklistService::class)->find('::ffff:11.0.7.9')?->ip)->toBe('11.0.7.0/24');
});
