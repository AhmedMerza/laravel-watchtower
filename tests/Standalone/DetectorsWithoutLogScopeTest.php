<?php

declare(strict_types=1);

use Illuminate\Auth\Events\Failed;
use Illuminate\Auth\Events\Lockout;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Schema;
use Watchtower\Enums\BlockSource;
use Watchtower\Tests\TestCase;

beforeAll(function () {
    TestCase::$beforeBoot = function ($app) {
        $app['config']->set('watchtower.auto_block.enabled', true);
        $app['config']->set('watchtower.auto_block.mode', 'block');

        foreach (['failed_logins', 'login_lockouts', 'scanner_paths', 'response_bursts'] as $detector) {
            $app['config']->set("watchtower.auto_block.detectors.{$detector}.enabled", true);
        }
    };
});

afterAll(function () {
    TestCase::$beforeBoot = null;
});

beforeEach(function () {
    // The shared TestCase creates a stand-in for LogScope's table so the
    // scheduled rule engine can be tested. Drop it: a detector that reaches
    // for it would now fail loudly rather than quietly pass on a table a
    // real standalone app doesn't have.
    Schema::dropIfExists('log_entries');

    expect(Schema::hasTable('log_entries'))->toBeFalse();
});

it('blocks a scanner probe with no log table present', function () {
    $this->withServerVariables(['REMOTE_ADDR' => '203.0.113.20'])
        ->get('/.git/config')
        ->assertForbidden();

    $this->assertDatabaseHas('blacklisted_ips', [
        'ip'     => '203.0.113.20',
        'source' => BlockSource::Auto->value,
    ]);
});

it('blocks a 404 burst with no log table present', function () {
    config()->set('watchtower.auto_block.detectors.response_bursts.count', 3);

    foreach (range(1, 3) as $i) {
        $this->withServerVariables(['REMOTE_ADDR' => '203.0.113.21'])
            ->get("/nothing-here-{$i}")
            ->assertNotFound();
    }

    $this->assertDatabaseHas('blacklisted_ips', ['ip' => '203.0.113.21']);
});

it('blocks repeated failed logins with no log table present', function () {
    config()->set('watchtower.auto_block.detectors.failed_logins.count', 3);

    Route::get('/attempt-login', function () {
        event(new Failed('web', null, ['email' => 'someone@example.com']));

        return 'tried';
    });

    foreach (range(1, 3) as $i) {
        $this->withServerVariables(['REMOTE_ADDR' => '203.0.113.22'])->get('/attempt-login');
    }

    $this->assertDatabaseHas('blacklisted_ips', [
        'ip'     => '203.0.113.22',
        'source' => BlockSource::Auto->value,
    ]);
});

it('blocks repeated login lockouts with no log table present', function () {
    config()->set('watchtower.auto_block.detectors.login_lockouts.count', 2);

    Route::get('/lock-out', function (Request $request) {
        event(new Lockout($request));

        return 'locked';
    });

    foreach (range(1, 2) as $i) {
        $this->withServerVariables(['REMOTE_ADDR' => '203.0.113.23'])->get('/lock-out');
    }

    $this->assertDatabaseHas('blacklisted_ips', [
        'ip'     => '203.0.113.23',
        'source' => BlockSource::Auto->value,
    ]);
});
