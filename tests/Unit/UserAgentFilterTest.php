<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Log;
use Watchtower\Services\UserAgentFilter;
use Watchtower\Support\FailureWindow;

beforeEach(function () {
    $this->filter = new UserAgentFilter;
});

afterEach(function () {
    FailureWindow::forget('user_agent_verify');
});

/**
 * A filter with the resolver stubbed out, so search-bot verification can be
 * exercised without reaching the network.
 *
 * Only the two raw lookups are stubbed — everything that interprets what
 * they return (the domain-suffix test, the record unpacking, the
 * forward-confirmation) is the real code.
 */
function fakeResolver(?string $ptr, array|false $forward = []): UserAgentFilter
{
    $filter = Mockery::mock(UserAgentFilter::class)
        ->makePartial()
        ->shouldAllowMockingProtectedMethods();

    $filter->shouldReceive('reverseLookup')->andReturn($ptr);
    $filter->shouldReceive('forwardLookup')->andReturn($forward);

    return $filter;
}

it('rejects the default User-Agent of every tool on the shipped deny list', function (string $agent, string $expected) {
    expect($this->filter->reject($agent, '203.0.113.9'))->toBe($expected);
})->with([
    'sqlmap'  => ['sqlmap/1.8.2#stable (https://sqlmap.org)', 'sqlmap'],
    'nikto'   => ['Mozilla/5.00 (Nikto/2.5.0) (Evasions:None) (Test:Port Check)', 'Nikto'],
    'wpscan'  => ['WPScan v3.8.22 (https://wpscan.com/wordpress-security-scanner)', 'WPScan'],
    'masscan' => ['masscan/1.3 (https://github.com/robertdavidgraham/masscan)', 'masscan'],
    'zgrab'   => ['Mozilla/5.0 zgrab/0.x', 'zgrab'],
]);

// The whole reason the default list is five names long. The big community
// "bad bot" lists include these, and shipping them would 403 webhooks,
// mobile apps, uptime monitors and paying API integrations on upgrade.
it('lets through the generic HTTP clients real integrations use', function (string $agent) {
    expect($this->filter->reject($agent, '203.0.113.9'))->toBeNull();
})->with([
    'curl'            => ['curl/8.5.0'],
    'python-requests' => ['python-requests/2.31.0'],
    'okhttp'          => ['okhttp/4.12.0'],
    'Go-http-client'  => ['Go-http-client/1.1'],
    'a browser'       => ['Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'],
]);

it('matches case-insensitively, since a tool built to evade varies its case', function () {
    expect($this->filter->reject('SQLMap/1.8', '203.0.113.9'))->toBe('SQLMap');
});

it('lets an allowed pattern override the deny list', function () {
    config()->set('watchtower.user_agents.allow', ['acme-security-audit']);

    // How you run your own pentest without dropping a pattern everyone else
    // benefits from: sqlmap --user-agent="sqlmap acme-security-audit".
    expect($this->filter->reject('sqlmap/1.8 acme-security-audit', '203.0.113.9'))->toBeNull();
});

it('treats patterns as literal substrings, not regexes', function () {
    config()->set('watchtower.user_agents.deny', ['w.scan']);

    // A `.` that matched any character would make half the deny lists
    // people paste in far broader than they read.
    expect($this->filter->reject('WPScan v3.8.22', '203.0.113.9'))->toBeNull()
        ->and($this->filter->reject('w.scan/1.0', '203.0.113.9'))->toBe('w.scan');
});

it('drops blank patterns instead of matching every request with them', function () {
    // One stray comma in an env list, or a trailing newline in a published
    // config, would otherwise compile to an empty alternative and reject
    // the entire internet.
    config()->set('watchtower.user_agents.deny', ['', '   ', 'sqlmap']);

    expect($this->filter->reject('curl/8.5.0', '203.0.113.9'))->toBeNull()
        ->and($this->filter->reject('sqlmap/1.8', '203.0.113.9'))->toBe('sqlmap');
});

it('recompiles when the patterns change rather than serving a stale regex', function () {
    config()->set('watchtower.user_agents.deny', ['aaa']);
    expect($this->filter->reject('aaa', '203.0.113.9'))->toBe('aaa');

    config()->set('watchtower.user_agents.deny', ['bbb']);

    expect($this->filter->reject('aaa', '203.0.113.9'))->toBeNull()
        ->and($this->filter->reject('bbb', '203.0.113.9'))->toBe('bbb');
});

it('ignores an empty deny list without calling into the regex engine', function () {
    config()->set('watchtower.user_agents.deny', []);

    expect($this->filter->reject('sqlmap/1.8', '203.0.113.9'))->toBeNull();
});

describe('search-bot verification', function () {
    beforeEach(function () {
        config()->set('watchtower.cache.store', 'array');
        config()->set('watchtower.user_agents.verify_search_bots.enabled', true);

        $this->googlebot = 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)';
    });

    it('does nothing at all while it is switched off', function () {
        config()->set('watchtower.user_agents.verify_search_bots.enabled', false);

        $filter = fakeResolver('anything.example.com');

        expect($filter->reject($this->googlebot, '66.249.66.1'))->toBeNull();

        $filter->shouldNotHaveReceived('reverseLookup');
    });

    it('lets through a crawler whose PTR resolves back to the same address', function () {
        $filter = fakeResolver('crawl-66-249-66-1.googlebot.com', ['66.249.66.1']);

        expect($filter->reject($this->googlebot, '66.249.66.1'))->toBeNull();
    });

    it('verifies an IPv6 crawler through the real dns_get_record shape', function () {
        // The mapping out of dns_get_record()'s record arrays is real logic
        // and the only thing standing between an IPv6 Googlebot and a
        // rejection. Stub the lookup, not the unpacking: a typo in the
        // `ipv6` key fails this test instead of quietly turning away every
        // IPv6 crawler in production.
        $filter = fakeResolver('crawl-ipv6.googlebot.com', [
            ['host' => 'crawl-ipv6.googlebot.com', 'class' => 'IN', 'type' => 'AAAA', 'ipv6' => '2001:4860:4801:0:0:0:0:1'],
        ]);

        expect($filter->reject($this->googlebot, '2001:4860:4801::1'))->toBeNull();
    });

    it('rejects an address whose PTR lookup is refused', function () {
        expect(fakeResolver(null)->reject($this->googlebot, '203.0.113.9'))
            ->toBe('unverified googlebot');
    });

    it('rejects an address with no PTR record, which echoes the address back', function () {
        // gethostbyaddr() returns the address unchanged when it cannot
        // answer. That is not a hostname and must never be compared as one.
        expect(fakeResolver('203.0.113.9')->reject($this->googlebot, '203.0.113.9'))
            ->toBe('unverified googlebot');
    });

    it('rejects a PTR pointing somewhere other than the bot\'s domains', function () {
        expect(fakeResolver('host.example.com', ['203.0.113.9'])->reject($this->googlebot, '203.0.113.9'))
            ->toBe('unverified googlebot');
    });

    it('rejects a lookalike domain that merely ends with the right letters', function () {
        // notgooglebot.com is not a subdomain of googlebot.com, and anyone
        // can register it.
        expect(fakeResolver('crawler.notgooglebot.com', ['203.0.113.9'])->reject($this->googlebot, '203.0.113.9'))
            ->toBe('unverified googlebot');
    });

    it('rejects a PTR under the right domain that does not resolve back', function () {
        // The forward half is the half that matters: whoever controls an
        // address controls its PTR and can point it at googlebot.com. Only
        // Google can make googlebot.com resolve to their address.
        expect(fakeResolver('fake.googlebot.com', ['66.249.66.1'])->reject($this->googlebot, '203.0.113.9'))
            ->toBe('unverified googlebot');
    });

    it('accepts a bot domain written with a leading dot', function () {
        config()->set('watchtower.user_agents.verify_search_bots.bots.googlebot', ['.googlebot.com']);

        expect(fakeResolver('crawl-1.googlebot.com', ['66.249.66.1'])->reject($this->googlebot, '66.249.66.1'))
            ->toBeNull();
    });

    it('caches a failing verdict, so a spoofer gets one lookup per TTL', function () {
        $filter = Mockery::mock(UserAgentFilter::class)
            ->makePartial()
            ->shouldAllowMockingProtectedMethods();

        // Once, not once per request — and for the FAILING verdict, which
        // is the one an address spoofing Googlebot would otherwise repeat
        // on every request of a scan.
        $filter->shouldReceive('reverseLookup')->once()->andReturn('host.example.com');
        $filter->shouldReceive('forwardLookup')->andReturn([]);

        foreach (range(1, 5) as $ignored) {
            expect($filter->reject($this->googlebot, '203.0.113.9'))->toBe('unverified googlebot');
        }
    });

    it('caches a passing verdict too, so a real crawler is not re-resolved', function () {
        $filter = Mockery::mock(UserAgentFilter::class)
            ->makePartial()
            ->shouldAllowMockingProtectedMethods();

        $filter->shouldReceive('reverseLookup')->once()->andReturn('crawl-66-249-66-1.googlebot.com');
        $filter->shouldReceive('forwardLookup')->once()->andReturn(['66.249.66.1']);

        foreach (range(1, 5) as $ignored) {
            expect($filter->reject($this->googlebot, '66.249.66.1'))->toBeNull();
        }
    });

    it('keys the verdict on the network a block would cover, not the bare address', function () {
        $filter = Mockery::mock(UserAgentFilter::class)
            ->makePartial()
            ->shouldAllowMockingProtectedMethods();

        // One lookup for the whole /64. Keyed on the exact address, an
        // attacker holding one /64 would have billions of free cache misses
        // — each a fresh blocking DNS call.
        $filter->shouldReceive('reverseLookup')->once()->andReturn(null);
        $filter->shouldReceive('forwardLookup')->andReturn([]);

        foreach (['2001:db8:1:2::1', '2001:db8:1:2::2', '2001:db8:1:2::dead:beef'] as $ip) {
            expect($filter->reject($this->googlebot, $ip))->toBe('unverified googlebot');
        }
    });

    it('stops looking up once the per-minute budget is spent', function () {
        config()->set('watchtower.user_agents.verify_search_bots.max_lookups_per_minute', 2);

        $filter = Mockery::mock(UserAgentFilter::class)
            ->makePartial()
            ->shouldAllowMockingProtectedMethods();

        // These are blocking resolver calls with no timeout, so the cap is
        // what bounds how much of the worker pool can be sitting in DNS.
        $filter->shouldReceive('reverseLookup')->twice()->andReturn(null);
        $filter->shouldReceive('forwardLookup')->andReturn([]);

        expect($filter->reject($this->googlebot, '203.0.113.1'))->toBe('unverified googlebot')
            ->and($filter->reject($this->googlebot, '203.0.113.2'))->toBe('unverified googlebot')
            // Over budget: the claim is trusted rather than resolved.
            ->and($filter->reject($this->googlebot, '203.0.113.3'))->toBeNull();
    });

    it('falls back to the deny list when there is no address to resolve', function () {
        $filter = fakeResolver(null);

        // An unverifiable claim must be judged like any other User-Agent,
        // not waved through. Treating "cannot check" as "verified" would
        // let the bot branch swallow the deny list, and `sqlmap Googlebot`
        // would sail past a list that names sqlmap.
        expect($filter->reject('sqlmap/1.8 Googlebot', null))->toBe('sqlmap');

        $filter->shouldNotHaveReceived('reverseLookup');
    });

    it('lets the claim through when the cache is unavailable, and says so once', function () {
        config()->set('watchtower.cache.store', 'no-such-store');

        Log::shouldReceive('channel')->andReturnSelf();
        Log::shouldReceive('error')->once();

        $filter = fakeResolver(null);

        // Without a cache we cannot bound the number of lookups, so we do
        // not look up at all: a resolver timeout on every request is a far
        // worse outcome than missing a fake crawler for a while. Silently
        // degrading to "trust every claim" is worse still, hence the log.
        expect($filter->reject($this->googlebot, '203.0.113.9'))->toBeNull()
            ->and($filter->reject($this->googlebot, '203.0.113.9'))->toBeNull();

        $filter->shouldNotHaveReceived('reverseLookup');
    });
});
