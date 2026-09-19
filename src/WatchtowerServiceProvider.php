<?php

declare(strict_types=1);

namespace Watchtower;

use Illuminate\Contracts\Auth\Access\Gate;
use Illuminate\Contracts\Http\Kernel;
use Illuminate\Http\Middleware\TrustProxies;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Schedule;
use Spatie\LaravelPackageTools\Package;
use Spatie\LaravelPackageTools\PackageServiceProvider;
use Watchtower\Console\Commands\CleanupCommand;
use Watchtower\Console\Commands\InstallCommand;
use Watchtower\Console\Commands\SyncCommand;
use Watchtower\Events\IpBlocked;
use Watchtower\Http\Controllers\BlockController;
use Watchtower\Http\Controllers\SyncController;
use Watchtower\Http\Middleware\Authorize;
use Watchtower\Http\Middleware\BlockedIpMiddleware;
use Watchtower\Http\Middleware\VerifySyncSignature;
use Watchtower\Listeners\NotifyOnBlock;
use Watchtower\Services\AutoBlockService;
use Watchtower\Services\BlacklistCache;
use Watchtower\Services\BlacklistService;
use Watchtower\Support\FailureWindow;
use Watchtower\Support\SyncSignature;

class WatchtowerServiceProvider extends PackageServiceProvider
{
    public function configurePackage(Package $package): void
    {
        $package
            ->name('watchtower')
            ->hasConfigFile()
            ->hasMigration('create_blacklisted_ips_table')
            ->runsMigrations()
            ->hasViews()
            ->hasCommands([InstallCommand::class, SyncCommand::class, CleanupCommand::class]);
    }

    public function registeringPackage(): void
    {
        $this->app->singleton(BlacklistCache::class);
        $this->app->singleton(BlacklistService::class);
        $this->app->singleton(AutoBlockService::class);
    }

    public function bootingPackage(): void
    {
        if (! config('watchtower.enabled', true)) {
            return;
        }

        $this->registerMiddleware();

        $this->defineGate();
        $this->registerRoutes();
        $this->registerSyncRoutes();

        Event::listen(IpBlocked::class, NotifyOnBlock::class);

        if (config('watchtower.auto_block.enabled', false)) {
            Schedule::call(fn () => $this->app->make(AutoBlockService::class)->run())
                ->everyMinute()
                ->name('watchtower:auto-block')
                ->withoutOverlapping();
        }

        if (config('watchtower.cleanup.enabled', true)) {
            Schedule::command('watchtower:cleanup')
                ->daily()
                ->name('watchtower:cleanup')
                ->withoutOverlapping();
        }
    }

    /**
     * Place the middleware directly after TrustProxies. Earlier, `$request->ip()`
     * is the load balancer's address rather than the client's, so blocks never
     * match; any later and sessions, auth and routing run for blocked IPs.
     * Without TrustProxies in the global stack, it goes first.
     */
    protected function registerMiddleware(): void
    {
        $kernel = $this->app->make(Kernel::class);
        $middleware = $kernel->getGlobalMiddleware();

        // prependMiddleware() skipped a middleware already in the stack;
        // array_splice() doesn't, so keep the guard ourselves rather than
        // risk running the whole blocklist check twice per request.
        if (in_array(BlockedIpMiddleware::class, $middleware, true)) {
            return;
        }

        // is_a() also matches an app's own subclass, e.g. App\Http\Middleware\TrustProxies,
        // and returns false for anything that isn't a class name, so it needs no is_string()
        // guard in front — which is just as well, since Laravel 13 narrowed this array's
        // PHPDoc to strings and PHPStan then reads such a guard as always-true on 13 only.
        $trustProxies = collect($middleware)->search(
            fn ($class) => is_a($class, TrustProxies::class, true)
        );

        if ($trustProxies === false) {
            $this->warnTrustProxiesMissing();
        }

        array_splice($middleware, $trustProxies === false ? 0 : $trustProxies + 1, 0, [BlockedIpMiddleware::class]);

        $kernel->setGlobalMiddleware($middleware);
    }

    /**
     * Running first without TrustProxies means `$request->ip()` is the direct
     * peer — behind a load balancer, the balancer. That silently reproduces
     * the bug this ordering exists to fix, so say so. Throttled, and only
     * reached in that branch: a stock stack never pays for this check.
     */
    private function warnTrustProxiesMissing(): void
    {
        if (FailureWindow::isOpen('proxies')) {
            return;
        }

        FailureWindow::open('proxies');

        try {
            Log::channel(config('watchtower.log_channel', 'stack'))
                ->warning('Watchtower: TrustProxies is not in the global middleware stack, so blocking runs first and sees the direct peer address. Behind a proxy or load balancer that is the proxy\'s IP, and blocks will never match.');
        } catch (\Throwable) {
            // A diagnostic must never break boot.
        }
    }

    protected function registerRoutes(): void
    {
        if (! config('watchtower.routes.enabled', true)) {
            return;
        }

        // LogScope-integrated mode: mount under LogScope's prefix and use
        // LogScope's authorization, so there's nothing extra to configure.
        //
        // Standalone mode: mount under Watchtower's own prefix, behind the
        // `viewWatchtower` Gate. The check is appended after
        // watchtower.routes.middleware, so that list can add to it but never
        // remove it.
        $logScopeAuthorize = $this->logScopeAuthorizeMiddleware();

        if ($logScopeAuthorize !== null) {
            $prefix = config('logscope.routes.prefix', 'logscope').'/watchtower';
            $domain = config('logscope.routes.domain');
            $middleware = array_merge(
                (array) config('logscope.routes.middleware', ['web']),
                [$logScopeAuthorize]
            );
        } else {
            $prefix = (string) config('watchtower.routes.prefix', 'watchtower');
            $domain = config('watchtower.routes.domain');
            $middleware = array_merge(
                (array) config('watchtower.routes.middleware', ['web']),
                [Authorize::class]
            );
        }

        // Named so the UI can build its URLs with route() instead of guessing
        // the prefix. The prefix is config-driven and has changed once already
        // (the guard → watchtower rename), which silently 404'd the Block IP
        // button for a whole release.
        Route::group([
            'prefix'     => $prefix,
            'middleware' => $middleware,
            'domain'     => $domain,
            'as'         => 'watchtower.api.',
        ], function () {
            Route::post('/api/block', [BlockController::class, 'block'])->name('block');
            Route::delete('/api/block/{ip}', [BlockController::class, 'unblock'])->where('ip', '.*')->name('unblock');
            Route::get('/api/status/{ip}', [BlockController::class, 'status'])->where('ip', '.*')->name('status');
            Route::get('/api/blocks', [BlockController::class, 'index'])->name('blocks');
        });
    }

    /**
     * LogScope's Authorize middleware when LogScope is installed, else null.
     */
    protected function logScopeAuthorizeMiddleware(): ?string
    {
        $class = 'LogScope\\Http\\Middleware\\Authorize';

        return class_exists($class) ? $class : null;
    }

    /**
     * The default `viewWatchtower` Gate: `local` only, guests included, as
     * Horizon does. An app grants access by defining the Gate itself, and
     * its definition wins whichever order the two run in: define() replaces
     * this one if the app runs later, and has() leaves the app's alone if it
     * ran first.
     */
    protected function defineGate(): void
    {
        $this->callAfterResolving(Gate::class, function (Gate $gate): void {
            if (! $gate->has('viewWatchtower')) {
                $gate->define('viewWatchtower', fn ($user = null): bool => $this->app->environment('local'));
            }
        });
    }

    /**
     * The master side of cross-environment sync.
     *
     * Registered only when a shared secret exists — an environment with no
     * WATCHTOWER_SYNC_SECRET is not a master and should expose nothing.
     * Deliberately independent of watchtower.routes.enabled, which governs
     * the human-facing management API: a master can turn that off and still
     * serve its satellites.
     *
     * No 'web' group. These are machine-to-machine calls with no session and
     * no CSRF token; VerifySyncSignature is the whole of the authentication.
     * The paths are fixed rather than config-driven because the satellite
     * signs the path it calls.
     */
    protected function registerSyncRoutes(): void
    {
        if (SyncSignature::secret() === '') {
            return;
        }

        Route::group([
            'middleware' => [VerifySyncSignature::class],
            'as'         => 'watchtower.sync.',
        ], function () {
            Route::get(SyncSignature::PULL_PATH, [SyncController::class, 'blocks'])->name('blocks');
            Route::post(SyncSignature::PUSH_PATH, [SyncController::class, 'receive'])->name('receive');
        });
    }
}
