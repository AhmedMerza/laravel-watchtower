<?php

declare(strict_types=1);

namespace Watchtower;

use Illuminate\Contracts\Http\Kernel;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Schedule;
use Spatie\LaravelPackageTools\Package;
use Spatie\LaravelPackageTools\PackageServiceProvider;
use Watchtower\Console\Commands\CleanupCommand;
use Watchtower\Console\Commands\InstallCommand;
use Watchtower\Console\Commands\SyncCommand;
use Watchtower\Events\IpBlocked;
use Watchtower\Http\Controllers\BlockController;
use Watchtower\Http\Middleware\BlockedIpMiddleware;
use Watchtower\Listeners\NotifyOnBlock;
use Watchtower\Services\AutoBlockService;
use Watchtower\Services\BlacklistCache;
use Watchtower\Services\BlacklistService;

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

        // Must run before sessions, auth, and LogScope's CaptureRequestContext
        $this->app->make(Kernel::class)->prependMiddleware(BlockedIpMiddleware::class);

        // Warm Redis from DB on boot if the key is missing (e.g. after Redis flush)
        $this->app->booted(function () {
            $this->app->make(BlacklistCache::class)->warmOnBoot();
        });

        $this->registerRoutes();

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

    protected function registerRoutes(): void
    {
        if (! config('watchtower.routes.enabled', true)) {
            return;
        }

        // LogScope-integrated mode: mount under LogScope's prefix and
        // automatically inherit LogScope's Authorize middleware so the
        // existing UI-as-LogScope-extension experience keeps working.
        //
        // Standalone mode: mount under Watchtower's own configured prefix
        // and use ONLY the middleware list from watchtower.routes.middleware.
        // Until proper standalone auth lands (PR 2), the host app is
        // responsible for restricting access via that middleware array
        // (e.g. ['web', 'auth'] + Gate check) or by disabling the routes
        // entirely via WATCHTOWER_ROUTES_ENABLED=false.
        $authorizeClass = 'LogScope\\Http\\Middleware\\Authorize';
        $logscopeInstalled = class_exists($authorizeClass);

        if ($logscopeInstalled) {
            $prefix = config('logscope.routes.prefix', 'logscope').'/watchtower';
            $domain = config('logscope.routes.domain');
            $middleware = array_merge(
                (array) config('logscope.routes.middleware', ['web']),
                [$authorizeClass]
            );
        } else {
            $prefix = (string) config('watchtower.routes.prefix', 'watchtower');
            $domain = config('watchtower.routes.domain');
            $middleware = (array) config('watchtower.routes.middleware', ['web']);
        }

        Route::group([
            'prefix'     => $prefix,
            'middleware' => $middleware,
            'domain'     => $domain,
        ], function () {
            Route::post('/api/block', [BlockController::class, 'block']);
            Route::delete('/api/block/{ip}', [BlockController::class, 'unblock'])->where('ip', '.*');
            Route::get('/api/status/{ip}', [BlockController::class, 'status'])->where('ip', '.*');
            Route::get('/api/blocks', [BlockController::class, 'index']);
        });
    }
}
