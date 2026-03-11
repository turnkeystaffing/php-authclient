<?php

declare(strict_types=1);

namespace Turnkey\AuthClient;

final class ScopeChecker
{
    /**
     * Check if claims contain a specific scope (exact, case-sensitive match).
     */
    public static function hasScope(?Claims $claims, string $scope): bool
    {
        if ($claims === null || $scope === '') {
            return false;
        }

        return in_array($scope, $claims->scopes, true);
    }

    /**
     * Check if claims contain any of the required scopes.
     */
    public static function hasAnyScope(?Claims $claims, array $requiredScopes): bool
    {
        if ($claims === null) {
            return false;
        }

        foreach ($requiredScopes as $scope) {
            if ($scope !== '' && in_array($scope, $claims->scopes, true)) {
                return true;
            }
        }

        return false;
    }
}
