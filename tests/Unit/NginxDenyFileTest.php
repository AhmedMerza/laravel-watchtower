<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Process;
use Watchtower\Support\NginxDenyFile;

beforeEach(function () {
    $this->dir = sys_get_temp_dir().'/watchtower-test-'.bin2hex(random_bytes(6));
    mkdir($this->dir);
    $this->path = $this->dir.'/watchtower-deny.conf';

    config()->set('watchtower.block_targets.nginx_file.path', $this->path);
    config()->set('watchtower.block_targets.nginx_file.reload_command', 'nginx -s reload');

    $this->file = new NginxDenyFile;

    // Not Process::fake() here: its catch-all '*' handler is matched before
    // any later per-command override a test registers (Str::is() picks the
    // first matching pattern in insertion order), so a test that needs a
    // specific command's result calls Process::fake([...]) itself instead.
});

afterEach(function () {
    foreach (glob($this->dir.'/*') ?: [] as $leftover) {
        unlink($leftover);
    }
    rmdir($this->dir);
});

// --- add() -------------------------------------------------------------------

it('creates the file with the header and a deny line', function () {
    Process::fake();

    $this->file->add('1.2.3.4');

    $contents = file_get_contents($this->path);

    expect($contents)->toContain(NginxDenyFile::HEADER)
        ->and($contents)->toContain('deny 1.2.3.4;');

    Process::assertRan('nginx -s reload');
});

it('is a true no-op when the value is already present — no rewrite, no reload', function () {
    // Also the single-process shape of the concurrent-worker race: two add()
    // calls for the identical value must produce exactly one write+reload
    // between them, whatever order two queue workers hit the lock in.
    Process::fake();

    $this->file->add('1.2.3.4');
    $before = file_get_contents($this->path);

    $this->file->add('1.2.3.4');
    $after = file_get_contents($this->path);

    expect($after)->toBe($before);
    Process::assertRanTimes('nginx -s reload', 1);
});

it('throws on a value IpRange::canonical() rejects, without writing or reloading', function () {
    Process::fake();

    expect(fn () => $this->file->add('not-an-ip'))
        ->toThrow(RuntimeException::class, 'not a valid IP or CIDR range');

    expect(is_file($this->path))->toBeFalse();
    Process::assertNothingRan();
});

// --- remove() ----------------------------------------------------------------

it('removes a present value and reloads', function () {
    Process::fake();

    $this->file->add('1.2.3.4');

    $this->file->remove('1.2.3.4');

    expect(file_get_contents($this->path))->not->toContain('deny 1.2.3.4;');
    Process::assertRanTimes('nginx -s reload', 2);
});

it('does nothing when the value is absent', function () {
    Process::fake();

    $this->file->remove('1.2.3.4');

    expect(is_file($this->path))->toBeFalse();
    Process::assertNothingRan();
});

it('does nothing on remove for a value that never could have been written', function () {
    Process::fake();

    $this->file->add('1.2.3.4');

    $this->file->remove('not-an-ip');

    expect(file_get_contents($this->path))->toContain('deny 1.2.3.4;');
    Process::assertRanTimes('nginx -s reload', 1);
});

// --- replaceAll() --------------------------------------------------------------

it('replaces the whole set in one write', function () {
    Process::fake();

    $this->file->add('9.9.9.9');

    $this->file->replaceAll(['1.2.3.4', '5.6.7.8']);

    $contents = file_get_contents($this->path);

    expect($contents)->toContain('deny 1.2.3.4;')
        ->and($contents)->toContain('deny 5.6.7.8;')
        ->and($contents)->not->toContain('deny 9.9.9.9;');
});

it('creates the file on a fresh install even when there is nothing active to write', function () {
    // Without this, "run watchtower:reconcile once ... before adding the
    // include" (docs/block-targets.md) does nothing on the single most
    // common first run — zero active blocks — and nginx's include then
    // fails to load because the file was never created.
    Process::fake();

    expect(is_file($this->path))->toBeFalse();

    $this->file->replaceAll([]);

    expect(is_file($this->path))->toBeTrue();
    Process::assertRanTimes('nginx -s reload', 1);
});

it('skips write and reload when the computed set already matches — the idempotency criterion', function () {
    Process::fake();

    $this->file->replaceAll(['1.2.3.4', '5.6.7.8']);

    $this->file->replaceAll(['5.6.7.8', '1.2.3.4']); // same set, different order

    Process::assertRanTimes('nginx -s reload', 1);
});

it('skips one unparseable value and still writes the rest of the batch', function () {
    Process::fake();
    config()->set('watchtower.log_channel', 'stack');

    Log::shouldReceive('channel')->with('stack')->andReturnSelf();
    Log::shouldReceive('warning')->once()->with(
        Mockery::pattern('/\[nginx_file\] could not reconcile one record/'),
        Mockery::on(fn ($ctx) => $ctx['ip'] === 'not-an-ip')
    );

    $this->file->replaceAll(['not-an-ip', '1.2.3.4']);

    $contents = file_get_contents($this->path);

    expect($contents)->toContain('deny 1.2.3.4;')
        ->and($contents)->not->toContain('not-an-ip');
});

// --- reload() ------------------------------------------------------------------

it('throws with the captured stderr when the reload command fails', function () {
    Process::fake(['nginx -s reload' => Process::result(exitCode: 1, errorOutput: 'nginx: [error] invalid config')]);

    expect(fn () => $this->file->add('1.2.3.4'))
        ->toThrow(RuntimeException::class, 'invalid config');
});

it('skips the reload entirely when no reload_command is configured', function () {
    Process::fake();
    config()->set('watchtower.block_targets.nginx_file.reload_command', null);

    $this->file->add('1.2.3.4');

    Process::assertNothingRan();
    expect(file_get_contents($this->path))->toContain('deny 1.2.3.4;');
});

// --- directory errors ------------------------------------------------------------

it('throws clearly when the directory does not exist', function () {
    config()->set('watchtower.block_targets.nginx_file.path', $this->dir.'/missing-subdir/denylist.conf');

    expect(fn () => $this->file->add('1.2.3.4'))
        ->toThrow(RuntimeException::class, "doesn't exist or isn't writable");
});
