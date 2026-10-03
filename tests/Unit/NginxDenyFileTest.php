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
        is_dir($leftover) ? rmdir($leftover) : unlink($leftover);
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

it('skips the rewrite but still reloads when the computed set already matches', function () {
    // The idempotency criterion is "no needless rewrite", not "no reload":
    // reload still has to run every time reconcile() is invoked, even with
    // nothing to rewrite, or a PRIOR reload that failed after a successful
    // write would never get retried (see the "repairs a previously failed
    // reload" test below). fileinode() unchanged proves no rename() ran —
    // content alone can't, since identical content written twice would look
    // the same either way.
    Process::fake();

    $this->file->replaceAll(['1.2.3.4', '5.6.7.8']);
    $inodeBefore = fileinode($this->path);

    $this->file->replaceAll(['5.6.7.8', '1.2.3.4']); // same set, different order

    expect(fileinode($this->path))->toBe($inodeBefore);
    Process::assertRanTimes('nginx -s reload', 2);
});

it('repairs a previously failed reload on the next reconcile, even with nothing to rewrite', function () {
    // The gap this guards: commit() writes successfully, then its own
    // reload() throws. The file is now correct but nginx was never told —
    // without this, the very next reconcile() would see content already
    // matching and skip retrying the reload forever.
    Process::fake(['nginx -s reload' => Process::result(exitCode: 1, errorOutput: 'nginx: [error] invalid config')]);

    expect(fn () => $this->file->replaceAll(['1.2.3.4']))->toThrow(RuntimeException::class);

    Process::fake(); // bare call replaces the handler map — reload now succeeds

    $this->file->replaceAll(['1.2.3.4']); // same set — would be a no-op content-wise

    // assertRanTimes, not assertRan: the first call's own (failed) attempt
    // already satisfies "ran at least once" on its own, so only a count
    // proves the second call retried rather than skipping the reload too.
    Process::assertRanTimes('nginx -s reload', 2);
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

it('throws with the captured stderr when the reload command fails, but still leaves the write durable', function () {
    Process::fake(['nginx -s reload' => Process::result(exitCode: 1, errorOutput: 'nginx: [error] invalid config')]);

    expect(fn () => $this->file->add('1.2.3.4'))
        ->toThrow(RuntimeException::class, 'invalid config');

    // commit() writes before it reloads — an admin should be able to trust
    // the file reflects the last attempted block even when nginx was never
    // told to pick it up.
    expect(file_get_contents($this->path))->toContain('deny 1.2.3.4;');
});

it('skips the reload entirely when no reload_command is configured', function () {
    Process::fake();
    config()->set('watchtower.block_targets.nginx_file.reload_command', null);

    $this->file->add('1.2.3.4');

    Process::assertNothingRan();
    expect(file_get_contents($this->path))->toContain('deny 1.2.3.4;');
});

// --- directory/lock errors raise OUR message, not a raw ErrorException -----------

it('throws its own message, not a raw ErrorException, when the lock file cannot be opened', function () {
    // Laravel's error handler converts fopen()'s warning on failure into a
    // thrown ErrorException before the `=== false` check below can ever
    // run — unless the call is @-suppressed. Forcing that failure here (the
    // lock path already exists as a directory, so fopen(..., 'c+') fails)
    // proves the suppression is actually in place, not just commented as
    // intent.
    mkdir($this->path.'.lock');

    expect(fn () => $this->file->add('1.2.3.4'))
        ->toThrow(RuntimeException::class, 'Could not open the lock file');
});

// --- permissions and locking -----------------------------------------------------

it('preserves the file\'s existing permissions across a rewrite', function () {
    // writeValues() always writes through a brand-new temp file, so without
    // this, a permission an admin set by hand (e.g. to give nginx's group
    // read access beyond this process's own umask) would be silently
    // reverted to the umask default on the very next block or unblock.
    Process::fake();

    $this->file->add('1.2.3.4');
    chmod($this->path, 0640);

    $this->file->add('5.6.7.8');

    expect(fileperms($this->path) & 0777)->toBe(0640);
});

it('locks the dedicated .lock file, never the data file itself', function () {
    // The concurrency-safety claim in withLock()'s docblock, proven rather
    // than just asserted: if NginxDenyFile locked the data file instead of
    // a dedicated sibling, holding an independent exclusive lock on the
    // data file here would make the add() below contend for it too.
    Process::fake();

    $this->file->add('1.2.3.4');

    $dataHandle = fopen($this->path, 'r+');
    flock($dataHandle, LOCK_EX);

    $this->file->add('5.6.7.8');

    flock($dataHandle, LOCK_UN);
    fclose($dataHandle);

    expect(file_get_contents($this->path))->toContain('deny 5.6.7.8;');
});

// --- directory errors ------------------------------------------------------------

it('throws clearly when the directory does not exist', function () {
    config()->set('watchtower.block_targets.nginx_file.path', $this->dir.'/missing-subdir/denylist.conf');

    expect(fn () => $this->file->add('1.2.3.4'))
        ->toThrow(RuntimeException::class, "doesn't exist or isn't writable");
});
