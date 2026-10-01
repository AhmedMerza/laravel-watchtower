<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Schema;

it('installs cleanly against a genuinely fresh app, without a double-registered migration crash (#104)', function () {
    $this->artisan('watchtower:install')->assertSuccessful();

    expect(Schema::hasTable('blacklisted_ips'))->toBeTrue();
    expect(Schema::hasTable('ip_offences'))->toBeTrue();
});

it('runs a second time without error, as a repeated watchtower:install would', function () {
    $this->artisan('watchtower:install')->assertSuccessful();
    $this->artisan('watchtower:install')->assertSuccessful();
});
