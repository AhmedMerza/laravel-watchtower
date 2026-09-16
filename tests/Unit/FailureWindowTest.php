<?php

declare(strict_types=1);

use Watchtower\Support\FailureWindow;

afterEach(function () {
    FailureWindow::forget('probe');
});

it('opens and closes a window backed by a marker file', function () {
    expect(FailureWindow::isOpen('probe'))->toBeFalse();

    FailureWindow::open('probe');

    expect(FailureWindow::isOpen('probe'))->toBeTrue();

    touch(storage_path('framework/watchtower-probe-failure'), time() - 61);

    expect(FailureWindow::isOpen('probe'))->toBeFalse();
});

it('still throttles in-process when the marker file cannot be written', function () {
    // Read-only container: storage/ isn't writable, so touch() fails and the
    // window can only live in memory. Without the fallback this returns false
    // forever and the caller logs on every single request — the exact flood
    // the class exists to prevent.
    app()->useStoragePath('/proc/watchtower-cannot-write-here');

    expect(FailureWindow::isOpen('probe'))->toBeFalse();

    FailureWindow::open('probe');

    expect(FailureWindow::isOpen('probe'))->toBeTrue();
});

it('keeps windows independent per name', function () {
    FailureWindow::open('probe');

    expect(FailureWindow::isOpen('probe'))->toBeTrue()
        ->and(FailureWindow::isOpen('cache'))->toBeFalse();
});
