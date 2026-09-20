<?php

declare(strict_types=1);

namespace Watchtower\Support;

use Illuminate\Support\Facades\Route;
use Watchtower\Exceptions\UnknownScopeException;

/**
 * The vocabulary of block scopes.
 *
 * A block with no scope covers the whole app, which is every block Watchtower
 * made before scopes existed. A scoped block covers only the routes carrying
 * `watchtower:{scope}`.
 *
 * Scope names are declared in `watchtower.scopes` and nowhere else. The list
 * exists so an undeclared name can be refused at the point it is written: a
 * block scoped to a name no route carries enforces nothing while reporting
 * itself as a block, and a typo is indistinguishable from a scope whose
 * middleware has not been wired up yet.
 */
final class BlockScope
{
    /**
     * A block that covers the whole app.
     *
     * Stored as '' rather than null so `(ip, scope)` can be a unique index:
     * MySQL, Postgres and SQLite all treat NULLs as distinct, which would let
     * one address hold two global rows.
     */
    public const GLOBAL = '';

    /**
     * The scope names the config declares, cleaned of blanks and duplicates.
     *
     * @return list<string>
     */
    public static function declared(): array
    {
        $scopes = array_map(
            static fn ($scope) => trim((string) $scope),
            array_values((array) config('watchtower.scopes', [])),
        );

        return array_values(array_unique(array_filter(
            $scopes,
            static fn (string $scope) => $scope !== self::GLOBAL,
        )));
    }

    public static function isDeclared(string $scope): bool
    {
        return in_array($scope, self::declared(), true);
    }

    /**
     * How many registered routes carry each `watchtower:{scope}` middleware.
     *
     * A declared scope with no routes is inert — blocks made in it enforce
     * nothing — and nothing at runtime can tell that apart from a scope whose
     * middleware simply hasn't been wired up yet. Counting them is what lets
     * `watchtower:install` say so out loud.
     *
     * @return array<string, int>
     */
    public static function routeCounts(): array
    {
        $counts = [];

        // ->getRoutes() twice: the facade hands back the RouteCollection, and
        // its own getRoutes() is the plain array. Iterating the collection
        // works at runtime but isn't typed as iterable.
        foreach (Route::getRoutes()->getRoutes() as $route) {
            foreach ($route->gatherMiddleware() as $middleware) {
                if (! is_string($middleware) || ! str_starts_with($middleware, 'watchtower:')) {
                    continue;
                }

                // `watchtower:auth,admin` is one middleware naming two scopes.
                foreach (explode(',', substr($middleware, strlen('watchtower:'))) as $scope) {
                    $scope = trim($scope);

                    if ($scope !== self::GLOBAL) {
                        $counts[$scope] = ($counts[$scope] ?? 0) + 1;
                    }
                }
            }
        }

        return $counts;
    }

    /**
     * Resolve what a caller asked for into a scope that can be stored.
     *
     * Deliberately `mixed` rather than `?string`. This reads a config value,
     * and every sibling key in the same array (`count`, `window_minutes`) is
     * an unquoted int — so `'scope' => 5` is an easy typo. Under strict_types
     * a `?string` parameter turns that into a TypeError, which callers do not
     * catch: it would escape `AutoBlockService::run()` and take out the whole
     * scheduled tick rather than the one misconfigured rule. A type mistake
     * is refused the same loud, contained way a name mistake is.
     *
     * @throws UnknownScopeException when the value isn't a declared name
     */
    public static function normalize(mixed $scope): string
    {
        if ($scope === null) {
            return self::GLOBAL;
        }

        if (! is_scalar($scope)) {
            throw new UnknownScopeException(sprintf(
                'A block scope must be a string, %s given.',
                get_debug_type($scope),
            ));
        }

        $scope = trim((string) $scope);

        if ($scope === self::GLOBAL) {
            return self::GLOBAL;
        }

        if (! self::isDeclared($scope)) {
            $declared = self::declared();

            throw new UnknownScopeException(sprintf(
                '"%s" is not a block scope this app declares. %s',
                $scope,
                $declared === []
                    ? 'No scopes are declared; add one to the `scopes` list in config/watchtower.php.'
                    : 'Declared scopes: '.implode(', ', $declared).'.',
            ));
        }

        return $scope;
    }
}
