<?php

declare(strict_types=1);

use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Schema;
use Watchtower\Console\Commands\ImportFirewallCommand;
use Watchtower\Enums\BlockSource;
use Watchtower\Events\IpBlocked;
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

it('keeps a live block as it is and replaces a lapsed one', function () {
    $service = app(BlacklistService::class);
    $service->block('45.9.20.5', ['reason' => 'mine', 'expires_at' => now()->addDay()]);
    $service->block('45.9.20.6', ['reason' => 'old', 'expires_at' => now()->subDay()]);
    config()->set('firewall.blacklist', ['45.9.20.5', '45.9.20.6']);

    $this->artisan('watchtower:import-firewall --commit')->assertSuccessful()
        ->expectsOutputToContain('skip   45.9.20.5 — already blocked')
        ->expectsOutputToContain('block  45.9.20.6');

    expect(BlacklistedIp::where('ip', '45.9.20.5')->value('reason'))->toBe('mine')
        ->and(BlacklistedIp::where('ip', '45.9.20.6')->sole()->expires_at)->toBeNull()
        ->and(app(BlacklistCache::class)->isBlocked('45.9.20.6'))->toBeTrue();
});
