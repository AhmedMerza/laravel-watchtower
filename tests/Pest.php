<?php

use Watchtower\Tests\SyncTestCase;
use Watchtower\Tests\TestCase;

uses(TestCase::class)->in(__DIR__.'/Feature', __DIR__.'/Unit');

// A master environment. Sync routes are registered from config at boot, so
// these need the secret in place before the app comes up — which is what
// SyncTestCase does and a beforeEach() cannot.
uses(SyncTestCase::class)->in(__DIR__.'/Sync');
