<?php

declare(strict_types=1);

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Http\Request;
use Watchtower\Http\Middleware\BlockedIpMiddleware;
use Watchtower\Http\Middleware\UserAgentMiddleware;
use Watchtower\Services\AutoBlockService;
use Watchtower\Services\UserAgentFilter;

beforeEach(function () {
    $this->autoBlock = Mockery::mock(AutoBlockService::class);
    $this->middleware = new UserAgentMiddleware(new UserAgentFilter, $this->autoBlock);
    $this->next = fn ($request) => response('ok', 200);
});

function uaRequest(?string $agent, string $ip = '203.0.113.9'): Request
{
    $request = Request::create('/test', 'GET');
    $request->server->set('REMOTE_ADDR', $ip);

    if ($agent !== null) {
        $request->headers->set('User-Agent', $agent);
    }

    return $request;
}

it('rejects a request from a tool on the deny list', function () {
    $this->autoBlock->shouldNotReceive('record');

    $response = $this->middleware->handle(uaRequest('sqlmap/1.8.2#stable (https://sqlmap.org)'), $this->next);

    expect($response->getStatusCode())->toBe(403);
});

it('answers with the configured block response, the same as an IP block', function () {
    config()->set('watchtower.block_response.status', 418);
    config()->set('watchtower.block_response.message', 'Nope.');
    $this->autoBlock->shouldNotReceive('record');

    $response = $this->middleware->handle(uaRequest('Nikto/2.5.0'), $this->next);

    expect($response->getStatusCode())->toBe(418)
        ->and($response->getContent())->toBe('Nope.');
});

it('passes an ordinary client through', function () {
    $response = $this->middleware->handle(uaRequest('curl/8.5.0'), $this->next);

    expect($response->getStatusCode())->toBe(200);
});

it('passes a request with no User-Agent at all through', function () {
    // Webhooks, health checks and uptime monitors send none. Treating that
    // as hostile is why people switch this kind of filtering back off.
    expect($this->middleware->handle(uaRequest(null), $this->next)->getStatusCode())->toBe(200)
        ->and($this->middleware->handle(uaRequest(''), $this->next)->getStatusCode())->toBe(200)
        ->and($this->middleware->handle(uaRequest('   '), $this->next)->getStatusCode())->toBe(200);
});

it('never turns away a never_block address, whatever it claims to be', function () {
    config()->set('watchtower.never_block', ['203.0.113.0/24']);

    $response = $this->middleware->handle(uaRequest('sqlmap/1.8.2'), $this->next);

    expect($response->getStatusCode())->toBe(200);
});

it('passes everything through when Watchtower is off', function () {
    config()->set('watchtower.enabled', false);

    expect($this->middleware->handle(uaRequest('sqlmap/1.8.2'), $this->next)->getStatusCode())->toBe(200);
});

it('passes everything through when the filter itself is off', function () {
    // Registration is decided at boot, so the middleware can still be in a
    // long-lived worker's stack after the flag is turned off.
    config()->set('watchtower.user_agents.enabled', false);

    expect($this->middleware->handle(uaRequest('sqlmap/1.8.2'), $this->next)->getStatusCode())->toBe(200);
});

it('does not block the address, only the request, while the detector is off', function () {
    // The User-Agent is written by the client, so a match is never on its
    // own grounds to block an address. Nothing is counted and nothing is
    // written unless bad_user_agent is armed deliberately.
    $this->autoBlock->shouldNotReceive('record');

    expect($this->middleware->handle(uaRequest('sqlmap/1.8.2'), $this->next)->getStatusCode())->toBe(403);
});

it('counts the rejection against the address once the detector is armed', function () {
    config()->set('watchtower.auto_block.detectors.bad_user_agent.enabled', true);

    $this->autoBlock->shouldReceive('record')
        ->once()
        ->with('bad_user_agent', '203.0.113.9', null, null)
        ->andReturn(false);

    expect($this->middleware->handle(uaRequest('sqlmap/1.8.2'), $this->next)->getStatusCode())->toBe(403);
});

it('counts against the network an IPv6 block would cover, not the bare address', function () {
    config()->set('watchtower.auto_block.detectors.bad_user_agent.enabled', true);

    // The middleware hands over the canonical address; widening it to the
    // block prefix is AutoBlockService's job, and this just proves the
    // address survives canonicalisation on the way there.
    $this->autoBlock->shouldReceive('record')
        ->once()
        ->with('bad_user_agent', '2001:db8::1', null, null)
        ->andReturn(false);

    $this->middleware->handle(uaRequest('sqlmap/1.8.2', '2001:0db8:0000::0001'), $this->next);
});

it('still rejects the request when the counted address is already blocked', function () {
    config()->set('watchtower.auto_block.detectors.bad_user_agent.enabled', true);

    // record() returning true means "already blocked, or blocked now"; the
    // answer to this request is the same either way.
    $this->autoBlock->shouldReceive('record')->once()->andReturn(true);

    expect($this->middleware->handle(uaRequest('sqlmap/1.8.2'), $this->next)->getStatusCode())->toBe(403);
});

it('names the signed-in user, so the shared-IP guard can see them', function () {
    config()->set('watchtower.auto_block.detectors.bad_user_agent.enabled', true);

    $user = Mockery::mock(Authenticatable::class);
    $user->shouldReceive('getAuthIdentifier')->andReturn(42);

    // A signed-in user behind a scanner User-Agent is exactly the case the
    // shared-IP guard exists to weigh. Every other test here runs
    // unauthenticated, so without this one a broken accessor or a cast that
    // dropped the id would leave the guard blind and nothing would fail.
    $this->autoBlock->shouldReceive('record')
        ->once()
        ->with('bad_user_agent', '203.0.113.9', 42, null)
        ->andReturn(false);

    $request = uaRequest('sqlmap/1.8.2');
    $request->setUserResolver(fn () => $user);

    expect($this->middleware->handle($request, $this->next)->getStatusCode())->toBe(403);
});

it('prefers the address the blocking middleware already resolved', function () {
    config()->set('watchtower.auto_block.detectors.bad_user_agent.enabled', true);

    // Symfony recomputes getClientIps() on every call, so the stashed value
    // saves re-walking the proxy chain. It must be USED, not just written:
    // a stash nobody reads is a silent no-op.
    $this->autoBlock->shouldReceive('record')
        ->once()
        ->with('bad_user_agent', '198.51.100.7', null, null)
        ->andReturn(false);

    $request = uaRequest('sqlmap/1.8.2');
    $request->attributes->set(BlockedIpMiddleware::CLIENT_IP, '198.51.100.7');

    $this->middleware->handle($request, $this->next);
});
