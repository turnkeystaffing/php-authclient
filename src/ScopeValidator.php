<?php

declare(strict_types=1);

namespace Turnkey\AuthClient;

/**
 * Validates scope name format following the service:resource:action convention.
 *
 * Valid formats:
 * - OIDC standard scopes: openid, profile, email, address, phone, offline_access
 * - 2-segment: resource:action (e.g. expenses:approve)
 * - 3-segment: service:resource:action (e.g. bgc:contractors:read)
 * - Wildcards: admin:*, bgc:contractors:*, *:*, *
 *
 * All segments must be lowercase alphanumeric/underscore. Wildcards (*) are only
 * allowed as the entire final segment.
 */
final class ScopeValidator
{
    private const MAX_NAME_LENGTH = 255;

    /**
     * Matches 2-3 segment scope names: first segment [a-z0-9_]+, followed by 1-2 segments
     * that may include wildcard (*).
     */
    private const NAME_PATTERN = '/^[a-z0-9_]+(?::[a-z0-9_*]+){1,2}$/';

    private const OIDC_STANDARD_SCOPES = [
        'openid' => true,
        'profile' => true,
        'email' => true,
        'address' => true,
        'phone' => true,
        'offline_access' => true,
    ];

    /**
     * Validate a scope name format.
     *
     * @throws \InvalidArgumentException on invalid scope name
     */
    public static function validateName(string $name): void
    {
        if ($name === '') {
            throw new \InvalidArgumentException('Scope name cannot be empty');
        }

        if (strlen($name) > self::MAX_NAME_LENGTH) {
            throw new \InvalidArgumentException(
                sprintf('Scope name cannot exceed %d characters', self::MAX_NAME_LENGTH),
            );
        }

        if ($name !== strtolower($name)) {
            throw new \InvalidArgumentException(
                sprintf('Scope names must be lowercase only, got: %s', $name),
            );
        }

        // OIDC standard scopes don't follow the resource:action pattern
        if (isset(self::OIDC_STANDARD_SCOPES[$name])) {
            return;
        }

        // Universal wildcards
        if ($name === '*:*' || $name === '*') {
            return;
        }

        if (!preg_match(self::NAME_PATTERN, $name)) {
            throw new \InvalidArgumentException(
                sprintf(
                    'Scope name must match pattern service:resource:action (2-3 segments, lowercase alphanumeric/underscore, * for wildcards), got: %s',
                    $name,
                ),
            );
        }

        if (str_contains($name, '*')) {
            self::validateWildcard($name);
        }
    }

    /**
     * Validate wildcard usage in a multi-segment scope name.
     * Called after regex check passes, only if name contains "*".
     */
    private static function validateWildcard(string $name): void
    {
        $segments = explode(':', $name);

        // Wildcard must be the entire segment, not embedded (e.g. "app*rove" is invalid)
        foreach (array_slice($segments, 1) as $seg) {
            if ($seg !== '*' && str_contains($seg, '*')) {
                throw new \InvalidArgumentException(
                    sprintf('Wildcard (*) must be the entire segment, not embedded within a segment name, got: %s', $name),
                );
            }
        }

        // Wildcard only allowed as the final segment (e.g. "bgc:*:read" is invalid)
        foreach (array_slice($segments, 0, -1) as $seg) {
            if ($seg === '*') {
                throw new \InvalidArgumentException(
                    sprintf('Wildcard (*) is only allowed as the final segment in a scope name, got: %s', $name),
                );
            }
        }
    }

    /**
     * Validate that a scope name's first segment matches the service code.
     * If serviceCode is null or empty, validation is skipped (backward compatibility).
     *
     * @throws \InvalidArgumentException on prefix mismatch
     */
    public static function validateScopePrefix(string $scopeName, ?string $serviceCode): void
    {
        if ($serviceCode === null || $serviceCode === '') {
            return;
        }

        $colonPos = strpos($scopeName, ':');
        if ($colonPos === false) {
            throw new \InvalidArgumentException(
                sprintf("Scope prefix must match service code '%s', but scope '%s' has no prefix segment", $serviceCode, $scopeName),
            );
        }

        $prefix = substr($scopeName, 0, $colonPos);
        if ($prefix !== $serviceCode) {
            throw new \InvalidArgumentException(
                sprintf("Scope prefix '%s' must match service code '%s'", $prefix, $serviceCode),
            );
        }
    }

    /**
     * Validate a list of scope names.
     *
     * @param string[] $names
     * @throws \InvalidArgumentException on any invalid scope name
     */
    public static function validateScopeNames(array $names): void
    {
        if (count($names) === 0) {
            throw new \InvalidArgumentException('Scope name list cannot be empty');
        }

        foreach ($names as $i => $name) {
            try {
                self::validateName($name);
            } catch (\InvalidArgumentException $e) {
                throw new \InvalidArgumentException(
                    sprintf('Scope name at index %d: %s', $i, $e->getMessage()),
                );
            }
        }
    }

    /**
     * Check if a scope name is a standard OIDC scope.
     */
    public static function isOidcStandardScope(string $name): bool
    {
        return isset(self::OIDC_STANDARD_SCOPES[$name]);
    }

    /**
     * Check if a scope name contains a wildcard.
     */
    public static function containsWildcard(string $name): bool
    {
        return str_contains($name, '*');
    }
}