<?php

declare(strict_types=1);

use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Schema;
use Watchtower\Console\Commands\ImportFirewallCommand;
use Watchtower\Enums\BlockSource;
use Watchtower\Events\IpBlocked;
use Watchtower\Events\IpUnblocked;
use Watchtower\Models\BlacklistedIp;
use Watchtower\Services\BlacklistCache;
use Watchtower\Services\BlacklistService;

/** antonioribeiro/firewall's own migration, as an app that used it still has it. */
function firewallTable(array $rows): void
{
    Schema::create('firewall', function (Blueprint $table) {
        $table->increments('id');
        $table->string('ip_address', 39)->unique()->index();
        $table->boolean('whitelisted')->default(false);
        $table->timestamps();
    });

    foreach ($rows as $ip => $whitelisted) {
        DB::table('firewall')->insert([
            'ip_address'  => $ip,
            'whitelisted' => $whitelisted,
            'created_at'  => '2019-03-04 05:06:07',
            'updated_at'  => '2020-01-02 03:04:05',
        ]);
    }
}

function importedIps(): array
{
    return BlacklistedIp::where('reason', ImportFirewallCommand::REASON)->orderBy('ip')->pluck('ip')->all();
}

it('reports every entry on a dry run and writes nothing', function () {
    firewallTable(['45.9.20.5' => false, '203.0.113.9' => true, 'country:br' => false]);
    config()->set('firewall.blacklist', ['host:office.example.com', 'not an ip', '31.13.0.0/16']);

    $this->artisan('watchtower:import-firewall')->assertSuccessful()
        ->expectsOutputToContain('block  45.9.20.5')
        ->expectsOutputToContain('block  31.13.0.0/16')
        ->expectsOutputToContain('skip   country:br — country entries need GeoIP')
        ->expectsOutputToContain('skip   host:office.example.com — a hostname resolves')
        ->expectsOutputToContain('skip   not an ip — not an address')
        ->expectsOutputToContain('WATCHTOWER_NEVER_BLOCK_IPS=127.0.0.1,::1,203.0.113.9')
        ->expectsOutputToContain('2 block(s) would be imported. Nothing was written');

    expect(BlacklistedIp::count())->toBe(0);
});

it('imports permanent manual blocks with the old timestamps, once', function () {
    Event::fake([IpBlocked::class]);
    firewallTable(['45.9.20.5' => false]);
    config()->set('firewall.blacklist', ['31.13.0.0/16']);

    $this->artisan('watchtower:import-firewall --commit')->assertSuccessful()
        ->expectsOutputToContain('Imported 2 block(s).')
        ->expectsOutputToContain('No block targets enabled.');

    $row = BlacklistedIp::where('ip', '45.9.20.5')->first();
    expect(importedIps())->toBe(['31.13.0.0/16', '45.9.20.5'])
        ->and($row->source)->toBe(BlockSource::Manual)
        ->and($row->expires_at)->toBeNull()
        ->and((string) $row->created_at)->toBe('2019-03-04 05:06:07')
        ->and((string) $row->updated_at)->toBe('2020-01-02 03:04:05')
        ->and(app(BlacklistCache::class)->isBlocked('45.9.20.5'))->toBeTrue()
        ->and(app(BlacklistCache::class)->isBlocked('31.13.200.1'))->toBeTrue();

    // One rebuild and one reconcile, not an event (notification + target push) per row.
    Event::assertNotDispatched(IpBlocked::class);

    $updated = BlacklistedIp::pluck('updated_at', 'ip')->all();

    $this->artisan('watchtower:import-firewall --commit')->assertSuccessful()
        ->expectsOutputToContain('skip   45.9.20.5 — already blocked')
        ->expectsOutputToContain('Imported 0 block(s).');

    expect(BlacklistedIp::pluck('updated_at', 'ip')->all())->toEqual($updated);
});

it('works from the config file alone, with the old package and its table gone', function () {
    config()->set('firewall.blacklist', ['45.9.20.5']);

    $this->artisan('watchtower:import-firewall --commit')->assertSuccessful();

    expect(importedIps())->toBe(['45.9.20.5']);
});

it('converts the old range forms to exactly the addresses they covered', function () {
    config()->set('firewall.blacklist', [
        '10.20.0.0/255.255.0.0',   // netmask
        '172.17.*.*',              // wildcard
        '45.9.20.1-45.9.20.10',    // dash range, unaligned at both ends
        '1.2.3.0/255.0.255.0',     // non-contiguous mask
        '1.*.3.*',                 // a wildcard in the middle
    ]);

    $this->artisan('watchtower:import-firewall --commit')->assertSuccessful()
        ->expectsOutputToContain('skip   1.2.3.0/255.0.255.0 — not an address')
        ->expectsOutputToContain('skip   1.*.3.* — not an address');

    expect(importedIps())->toEqualCanonicalizing([
        '10.20.0.0/16', '172.17.0.0/16',
        '45.9.20.1', '45.9.20.2/31', '45.9.20.4/30', '45.9.20.8/31', '45.9.20.10',
    ]);

    $cache = app(BlacklistCache::class);
    expect($cache->isBlocked('45.9.20.0'))->toBeFalse()
        ->and($cache->isBlocked('45.9.20.7'))->toBeTrue()
        ->and($cache->isBlocked('45.9.20.11'))->toBeFalse();
});

it('reads files named in the config, but not ones a table row names', function () {
    $dir = sys_get_temp_dir().'/watchtower-firewall-'.uniqid();
    mkdir($dir);
    file_put_contents("{$dir}/nested.txt", "45.9.20.6\n{$dir}/list.txt\n");
    file_put_contents("{$dir}/list.txt", "45.9.20.5\n\n{$dir}/nested.txt\n");

    firewallTable(["{$dir}/nested.txt" => false]);
    config()->set('firewall.blacklist', ["{$dir}/list.txt"]);

    try {
        $this->artisan('watchtower:import-firewall --commit')->assertSuccessful()
            ->expectsOutputToContain("skip   {$dir}/nested.txt — not an address");
    } finally {
        array_map('unlink', glob("{$dir}/*"));
        rmdir($dir);
    }

    expect(importedIps())->toBe(['45.9.20.5', '45.9.20.6']);
});

it('skips what the whitelist, never_block or the breadth limit keeps unblocked', function () {
    config()->set('watchtower.never_block', ['127.0.0.1', '198.51.100.0/24']);
    firewallTable(['45.9.20.5' => true, '45.9.20.0/24' => false]);
    config()->set('firewall.whitelist', ['198.51.100.7']);
    config()->set('firewall.blacklist', ['45.9.20.5', '198.51.100.7', '10.0.0.0/8', '2001:db8:1::7']);

    $this->artisan('watchtower:import-firewall --commit')->assertSuccessful()
        ->expectsOutputToContain('skip   45.9.20.5 — also whitelisted')
        // The whitelisted address inside it gets through via never_block,
        // as it got through the old package; the rest stays blocked.
        ->expectsOutputToContain('block  45.9.20.0/24')
        ->expectsOutputToContain('skip   198.51.100.7 — also whitelisted')
        ->expectsOutputToContain('skip   10.0.0.0/8 — broader than /16')
        // Only what never_block lacks, after what it already holds.
        ->expectsOutputToContain('WATCHTOWER_NEVER_BLOCK_IPS=127.0.0.1,198.51.100.0/24,45.9.20.5')
        ->expectsOutputToContain("'never_block' => ['127.0.0.1', '198.51.100.0/24', '45.9.20.5'],");

    // A lone IPv6 address is stored the way block() stores it.
    expect(importedIps())->toBe(['2001:db8:1::/64', '45.9.20.0/24']);
});

it('keeps a permanent block as it is, and replaces one that would lapse', function () {
    $service = app(BlacklistService::class);
    $service->block('45.9.20.5', ['reason' => 'mine']);
    $service->block('45.9.20.6', ['reason' => 'old', 'expires_at' => now()->subDay()]);
    $service->block('45.9.20.7', ['reason' => 'for now', 'expires_at' => now()->addDay()]);
    $service->block('45.9.20.8', ['reason' => 'listed', 'source' => BlockSource::Feed]);
    config()->set('firewall.blacklist', ['45.9.20.5', '45.9.20.6', '45.9.20.7', '45.9.20.8']);

    $this->artisan('watchtower:import-firewall --commit')->assertSuccessful()
        ->expectsOutputToContain('skip   45.9.20.5 — already blocked')
        ->expectsOutputToContain('block  45.9.20.7 — replaces a temporary or feed block')
        ->expectsOutputToContain('Imported 3 block(s).');

    expect(BlacklistedIp::where('ip', '45.9.20.5')->value('reason'))->toBe('mine')
        ->and(BlacklistedIp::count())->toBe(4)
        ->and(importedIps())->toBe(['45.9.20.6', '45.9.20.7', '45.9.20.8'])
        ->and(BlacklistedIp::whereNotNull('expires_at')->orWhere('source', BlockSource::Feed)->count())->toBe(0)
        ->and(app(BlacklistCache::class)->isBlocked('45.9.20.6'))->toBeTrue();
});

it('checks a lone IPv6 address against the lists before widening it', function () {
    config()->set('watchtower.never_block', ['2001:db8:1::7']);
    config()->set('firewall.whitelist', ['2001:db8:2::7']);
    config()->set('firewall.blacklist', ['2001:db8:1::7', '2001:db8:2::7', '2001:db8:3::7']);

    $this->artisan('watchtower:import-firewall --commit')->assertSuccessful()
        ->expectsOutputToContain('skip   2001:db8:1::7 — covered by never_block')
        ->expectsOutputToContain('skip   2001:db8:2::7 — also whitelisted');

    expect(importedIps())->toBe(['2001:db8:3::/64']);
});

it('keeps the earliest listing of a target, and fills in missing timestamps', function () {
    firewallTable(['45.9.20.5' => false, '45.9.20.6' => false]);
    // The same address again, padded: the column is unique, the trimmed value isn't.
    DB::table('firewall')->insert(['ip_address' => ' 45.9.20.5 ', 'whitelisted' => false, 'created_at' => '2017-01-01 00:00:00', 'updated_at' => null]);
    DB::table('firewall')->where('ip_address', '45.9.20.6')->update(['created_at' => null, 'updated_at' => null]);
    // A pre-nullable-timestamps table's zero date, which strict MySQL won't take back.
    DB::table('firewall')->insert(['ip_address' => '45.9.20.7', 'whitelisted' => false, 'created_at' => '0000-00-00 00:00:00', 'updated_at' => '0000-00-00 00:00:00']);

    $this->artisan('watchtower:import-firewall --commit')->assertSuccessful();

    $rows = BlacklistedIp::get()->keyBy('ip');
    expect(importedIps())->toBe(['45.9.20.5', '45.9.20.6', '45.9.20.7'])
        // Listed by the 2019 row and the 2017 one: the earlier date wins,
        // and its missing updated_at falls back to its created_at.
        ->and((string) $rows['45.9.20.5']->created_at)->toBe('2017-01-01 00:00:00')
        ->and((string) $rows['45.9.20.5']->updated_at)->toBe('2017-01-01 00:00:00')
        ->and($rows['45.9.20.6']->created_at)->not->toBeNull()
        // The raw column: Carbon would read a zero date back as -0001-11-30.
        ->and(DB::table('blacklisted_ips')->where('ip', '45.9.20.7')->value('created_at'))->not->toStartWith('0000')
        ->and(DB::table('blacklisted_ips')->where('ip', '45.9.20.7')->value('updated_at'))->not->toStartWith('0000')
        ->and($rows['45.9.20.6']->source_env)->toBe(app()->environment());
});

it('converts the edge cases of a dash range', function () {
    config()->set('firewall.blacklist', [
        '45.9.20.5-45.9.20.5',
        '45.9.21.10-45.9.21.1',
        '255.255.255.254-255.255.255.255',
    ]);

    $this->artisan('watchtower:import-firewall')->assertSuccessful()
        ->expectsOutputToContain('block  45.9.20.5')
        ->expectsOutputToContain('skip   45.9.21.10-45.9.21.1 — not an address')
        ->expectsOutputToContain('block  255.255.255.254/31');
});

it('fails, and recovers on a re-run, when the cache rebuild fails', function () {
    config()->set('firewall.blacklist', ['45.9.20.5']);
    // The first rebuild fails; later ones run for real.
    $real = app(BlacklistCache::class);
    $calls = 0;
    $this->partialMock(BlacklistCache::class)->shouldReceive('rebuild')
        ->andReturnUsing(function () use ($real, &$calls) {
            return $calls++ > 0 && $real->rebuild();
        });

    $this->artisan('watchtower:import-firewall --commit')->assertFailed()
        ->expectsOutputToContain('the cache rebuild failed')
        ->doesntExpectOutputToContain('No block targets enabled.');

    expect(importedIps())->toBe(['45.9.20.5']);

    // Nothing new to import, but the rebuild and the reconcile still run.
    $this->artisan('watchtower:import-firewall --commit')->assertSuccessful()
        ->expectsOutputToContain('Imported 0 block(s).')
        ->expectsOutputToContain('No block targets enabled.');

    expect($calls)->toBe(2)->and($real->isBlocked('45.9.20.5'))->toBeTrue();
});

it('escapes what an old row holds, and does not suggest a huge whitelist entry', function () {
    firewallTable(['<error>x</error>' => false, '0.0.0.0/0' => true]);

    $this->artisan('watchtower:import-firewall')->assertSuccessful()
        ->expectsOutputToContain('skip   <error>x</error> — not an address')
        ->expectsOutputToContain('Whitelisted 0.0.0.0/0 is too broad to suggest')
        ->doesntExpectOutputToContain('WATCHTOWER_NEVER_BLOCK_IPS=');
});

it('handles a list larger than one chunk', function () {
    config()->set('firewall.blacklist', array_map(fn ($i) => '45.9.'.intdiv($i, 256).'.'.($i % 256), range(0, 1200)));

    $this->artisan('watchtower:import-firewall --commit')->assertSuccessful()
        ->expectsOutputToContain('Imported 1201 block(s).');

    $this->artisan('watchtower:import-firewall --commit')->assertSuccessful()
        ->expectsOutputToContain('Imported 0 block(s).');

    // Undone across chunks too: deleting while paging must not skip rows.
    $this->artisan('watchtower:import-firewall --undo --commit')->assertSuccessful()
        ->expectsOutputToContain('Removed 1201 imported block(s).');

    expect(BlacklistedIp::count())->toBe(0);
});

it('undoes an import, and leaves alone what it did not add', function () {
    config()->set('firewall.blacklist', ['45.9.20.5', '45.9.20.6', '45.9.20.0/24']);
    app(BlacklistService::class)->block('45.9.21.1', ['reason' => 'mine']);
    $this->artisan('watchtower:import-firewall --commit')->assertSuccessful();

    // Re-blocked by hand since: the reason is the admin's now.
    app(BlacklistService::class)->block('45.9.20.6', ['reason' => 'still bad']);

    $this->artisan('watchtower:import-firewall --undo')->assertSuccessful()
        ->expectsOutputToContain('2 imported block(s) would be removed. Nothing was written');
    expect(importedIps())->toBe(['45.9.20.0/24', '45.9.20.5']);

    Event::fake([IpUnblocked::class]);
    $this->artisan('watchtower:import-firewall --undo --commit')->assertSuccessful()
        ->expectsOutputToContain('Removed 2 imported block(s).');

    $cache = app(BlacklistCache::class);
    expect(importedIps())->toBe([])
        ->and(BlacklistedIp::orderBy('ip')->pluck('ip')->all())->toBe(['45.9.20.6', '45.9.21.1'])
        ->and($cache->isBlocked('45.9.20.5'))->toBeFalse()
        ->and($cache->isBlocked('45.9.20.9'))->toBeFalse()
        ->and($cache->isBlocked('45.9.20.6'))->toBeTrue();

    Event::assertDispatchedTimes(IpUnblocked::class, 2);
    Event::assertDispatched(IpUnblocked::class, fn ($event) => $event->ip === '45.9.20.0/24');
});
