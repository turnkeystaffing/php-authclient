<?php

declare(strict_types=1);

namespace Turnkey\AuthClient;

final class ScopeChecker
{
    /**
     * Check if claims contain a scope matching the required scope.
     * Supports wildcard matching in user scopes (e.g. user has "admin:*", required "admin:read" → true).
     * Wildcards only apply in the user's direction — a specific user scope never satisfies a wildcard requirement.
     */
    public static function hasScope(?Claims $claims, string $scope): bool
    {
        if ($claims === null || $scope === '') {
            return false;
        }

        foreach ($claims->scopes as $userScope) {
            if ($userScope === $scope) {
                return true;
            }

            if (str_contains($userScope, '*') && self::matchesPattern($userScope, $scope)) {
                return true;
            }
        }

        return false;
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
            if ($scope !== '' && self::hasScope($claims, $scope)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Check if claims contain all of the required scopes.
     */
    public static function hasAllScopes(?Claims $claims, array $requiredScopes): bool
    {
        if ($claims === null) {
            return false;
        }

        foreach ($requiredScopes as $scope) {
            if (!self::hasScope($claims, $scope)) {
                return false;
            }
        }

        return true;
    }

    /**
     * Check if a wildcard pattern matches a scope name.
     *
     * Rules:
     * - "*:*" or "*" matches any scope (universal wildcard)
     * - Trailing wildcard matches all remaining segments: "expenses:*" matches "expenses:approve"
     * - "bgc:*" matches "bgc:contractors:read" (service-level wildcard spans sub-segments)
     * - Non-final wildcards match exactly one segment
     * - Empty segments (trailing colons) never match
     */
    public static function matchesPattern(string $pattern, string $scopeName): bool
    {
        if ($pattern === $scopeName) {
            return true;
        }

        if ($pattern === '*:*' || $pattern === '*') {
            return true;
        }

        if (!str_contains($pattern, '*')) {
            return false;
        }

        $patternParts = explode(':', $pattern);
        $scopeParts = explode(':', $scopeName);

        // Reject empty segments (e.g. "a:b:" or ":a")
        foreach ($patternParts as $pp) {
            if ($pp === '') {
                return false;
            }
        }
        foreach ($scopeParts as $sp) {
            if ($sp === '') {
                return false;
            }
        }

        foreach ($patternParts as $i => $pp) {
            if ($pp === '*' && $i === count($patternParts) - 1) {
                // Trailing wildcard: matches everything remaining, but scope must have at least one segment here
                return $i < count($scopeParts);
            }
            if ($i >= count($scopeParts)) {
                return false;
            }
            if ($pp === '*') {
                // Non-final wildcard: match any single segment
                continue;
            }
            if ($pp !== $scopeParts[$i]) {
                return false;
            }
        }

        // All pattern parts matched — scope must not have extra unmatched segments
        return count($patternParts) === count($scopeParts);
    }
}
