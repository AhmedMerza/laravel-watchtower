<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Http;
use Watchtower\Support\CloudflareApi;

if (! function_exists('cfParseQuery')) {
    // parse_str() mangles dots in parameter names into underscores, which
    // would silently break every "configuration.target"/"configuration.value"
    // assertion below — this keeps dotted keys intact.
    function cfParseQuery(string $url): array
    {
        $query = [];

        foreach (explode('&', (string) parse_url($url, PHP_URL_QUERY)) as $pair) {
            if ($pair === '') {
                continue;
            }

            [$key, $value] = array_pad(explode('=', $pair, 2), 2, '');
            $query[urldecode($key)] = urldecode($value);
        }

        return $query;
    }
}

beforeEach(function () {
    config()->set('watchtower.block_targets.cloudflare.account_id', 'acct123');
    config()->set('watchtower.block_targets.cloudflare.api_token', 'test-token');

    $this->api = new CloudflareApi;
    $this->rulesUrl = 'https://api.cloudflare.com/client/v4/accounts/acct123/firewall/access_rules/rules';
});

it('finds an existing rule by target and value', function () {
    Http::fake([
        $this->rulesUrl.'*' => Http::response([
            'result' => [
                ['id' => 'rule1', 'mode' => 'block', 'notes' => CloudflareApi::NOTE],
            ],
        ], 200),
    ]);

    expect($this->api->findRule('ip', '1.2.3.4'))
        ->toBe(['id' => 'rule1', 'mode' => 'block', 'notes' => CloudflareApi::NOTE]);

    Http::assertSent(function ($request) {
        $query = cfParseQuery($request->url());

        return $request->method() === 'GET'
            && ($query['configuration.target'] ?? null) === 'ip'
            && ($query['configuration.value'] ?? null) === '1.2.3.4';
    });
});

it('returns null when no rule matches', function () {
    Http::fake([$this->rulesUrl.'*' => Http::response(['result' => []], 200)]);

    expect($this->api->findRule('ip', '1.2.3.4'))->toBeNull();
});

it('throws when the lookup fails', function () {
    Http::fake([$this->rulesUrl.'*' => Http::response([], 500)]);

    expect(fn () => $this->api->findRule('ip', '1.2.3.4'))
        ->toThrow(RuntimeException::class, 'HTTP 500');
});

it('creates a rule tagged with the watchtower marker', function () {
    Http::fake([$this->rulesUrl => Http::response(['result' => ['id' => 'new-rule']], 200)]);

    expect($this->api->create('ip', '1.2.3.4'))->toBe('new-rule');

    Http::assertSent(function ($request) {
        return $request->method() === 'POST'
            && $request['mode'] === 'block'
            && $request['notes'] === CloudflareApi::NOTE
            && $request['configuration'] === ['target' => 'ip', 'value' => '1.2.3.4'];
    });
});

it('throws when create fails', function () {
    Http::fake([$this->rulesUrl => Http::response([], 400)]);

    expect(fn () => $this->api->create('ip', '1.2.3.4'))
        ->toThrow(RuntimeException::class, 'HTTP 400');
});

it('deletes a rule by id', function () {
    Http::fake([$this->rulesUrl.'/rule1' => Http::response(['result' => ['id' => 'rule1']], 200)]);

    $this->api->delete('rule1');

    Http::assertSent(fn ($request) => $request->method() === 'DELETE'
        && $request->url() === $this->rulesUrl.'/rule1');
});

it('throws when delete fails', function () {
    Http::fake([$this->rulesUrl.'/rule1' => Http::response([], 404)]);

    expect(fn () => $this->api->delete('rule1'))
        ->toThrow(RuntimeException::class, 'HTTP 404');
});

it('lists every managed rule across pages, excluding anything not exactly tagged', function () {
    $pageOne = array_map(fn ($i) => [
        'id'            => "rule-{$i}",
        'notes'         => CloudflareApi::NOTE,
        'configuration' => ['target' => 'ip', 'value' => "10.0.0.{$i}"],
    ], range(1, 100));

    $pageTwo = [
        ['id' => 'rule-101', 'notes' => CloudflareApi::NOTE, 'configuration' => ['target' => 'ip', 'value' => '10.0.0.101']],
        // Notes merely CONTAINS something similar, not an exact match — must
        // be excluded, since the API's own `notes` filter isn't trusted to
        // be exact (see CloudflareApi::listManaged()'s comment).
        ['id' => 'foreign', 'notes' => 'some other note mentioning watchtower', 'configuration' => ['target' => 'ip', 'value' => '10.0.0.200']],
    ];

    Http::fake(function ($request) use ($pageOne, $pageTwo) {
        $query = cfParseQuery($request->url());
        $page = (int) ($query['page'] ?? 1);

        return Http::response(['result' => $page === 1 ? $pageOne : $pageTwo], 200);
    });

    $managed = $this->api->listManaged();

    expect($managed)->toHaveCount(101)
        ->and($managed)->toHaveKey('10.0.0.1', 'rule-1')
        ->and($managed)->toHaveKey('10.0.0.101', 'rule-101')
        ->and($managed)->not->toHaveKey('10.0.0.200');
});
