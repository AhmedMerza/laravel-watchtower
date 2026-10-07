<?php

declare(strict_types=1);

namespace Watchtower\Support;

use Illuminate\Support\Facades\Route;

/**
 * Where alerts go and the link they carry — shared by the instant alert and
 * the daily digest (#124).
 */
final class AlertChannels
{
    /**
     * Channel => route, keeping only the ones given a value, so an unset env
     * var turns its channel off. A comma-separated mail route becomes a list.
     *
     * @param  array<string, mixed>  $routes
     * @return array<string, mixed>
     */
    public static function routes(array $routes): array
    {
        $routes = array_filter($routes, fn ($route) => $route !== null && $route !== '' && $route !== []);

        if (is_string($routes['mail'] ?? null)) {
            $routes['mail'] = array_values(array_filter(array_map('trim', explode(',', $routes['mail']))));
        }

        return $routes;
    }

    /**
     * The management page link, or null with the UI off. The instant alert
     * resolves it at the block, not in the queued job.
     *
     * Rooted at APP_URL, never at the current request. A real-time detector
     * blocks inside the very request it caught, and route() would take that
     * request's Host header — the attacker's — and put their link in the
     * operator's security alert. A UI route with its own domain is built from
     * that domain, which no request can change.
     */
    public static function link(): ?string
    {
        $route = Route::getRoutes()->getByName('watchtower.ui.index');

        if ($route === null) {
            return null;
        }

        // An alert without a link beats no alert: a domain with a parameter
        // in it ({tenant}.example.com) can't be built from here, and an empty
        // APP_URL would give a link with no host.
        return rescue(fn () => match (true) {
            $route->getDomain() !== null           => route('watchtower.ui.index'),
            (string) config('app.url') === ''      => null,
            default                                => rtrim((string) config('app.url'), '/').route('watchtower.ui.index', [], false),
        }, null, report: false);
    }
}
