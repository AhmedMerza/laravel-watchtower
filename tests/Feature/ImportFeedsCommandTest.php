<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Queue;
use Illuminate\Support\Facades\Route;
use Watchtower\Console\Commands\ImportFeedsCommand;
use Watchtower\Enums\BlockSource;
use Watchtower\Events\IpBlocked;
use Watchtower\Jobs\PushBlockToMaster;
use Watchtower\Models\BlacklistedIp;
use Watchtower\Services\BlacklistCache;
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
    $start = hrtime(true);

    for ($i = 0; $i < $lookups; $i++) {
        $cache->isBlocked('8.8.'.($i % 256).'.8');
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
