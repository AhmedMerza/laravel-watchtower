<?php

declare(strict_types=1);

it('tells a standalone install to define the viewWatchtower Gate, at the mounted prefix (#51)', function () {
    $this->artisan('watchtower:install')
        ->expectsOutputToContain('Standalone mode — Watchtower routes mounted at /watchtower')
        ->expectsOutputToContain("Gate::define('viewWatchtower', fn (\$user) => \$user->isAdmin());")
        ->doesntExpectOutputToContain('LogScope detected')
        ->assertSuccessful();
});
