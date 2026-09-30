<?php

declare(strict_types=1);

namespace Turnkey\AuthClient\Discovery;

use Turnkey\AuthClient\ScopeValidator;

/**
 * Validates a ScopeManifest, collecting all issues.
 *
 * CONTRACT: Rules match go-authclient's ValidateManifest, which in turn mirrors
 * get-native-auth's scope name contract. Divergence causes sync failures.
 */
final class ManifestValidator
{
    public const MAX_SCOPES = 10000;
    public const MAX_TEMPLATES = 1000;
    public const MAX_TEMPLATE_NAME_LENGTH = 255;
    public const MAX_VALIDATION_ERRORS = 50;

    private const SERVICE_CODE_PATTERN = '/^[a-z0-9_]+$/';

    /**
     * @throws ManifestValidationException if any issues are found
     */
    public static function validate(ScopeManifest $manifest): void
    {
        $errors = [];

        $serviceCodeError = self::validateServiceCode($manifest->serviceCode);
        $serviceCodeValid = $serviceCodeError === null;
        if (!$serviceCodeValid) {
            $errors[] = $serviceCodeError;
        }

        $scopesDefined = count($manifest->scopes) > 0;
        if (!$scopesDefined) {
            $errors[] = 'at least one scope is required';
        }
        if (count($manifest->scopes) > self::MAX_SCOPES) {
            $errors[] = sprintf('too many scopes: %d (max %d)', count($manifest->scopes), self::MAX_SCOPES);
            throw new ManifestValidationException($errors);
        }
        if (count($manifest->templates) > self::MAX_TEMPLATES) {
            $errors[] = sprintf('too many templates: %d (max %d)', count($manifest->templates), self::MAX_TEMPLATES);
            throw new ManifestValidationException($errors);
        }

        $scopeSet = [];
        foreach ($manifest->scopes as $scope) {
            if ($serviceCodeValid) {
                $error = self::validateScopeName($scope->name, $manifest->serviceCode);
                if ($error !== null) {
                    $errors[] = $error;
                }
            }
            if ($scope->name !== '' && isset($scopeSet[$scope->name])) {
                $errors[] = sprintf('duplicate scope name "%s"', $scope->name);
            }
            if ($scope->name !== '') {
                $scopeSet[$scope->name] = true;
            }
        }

        $templateNames = [];
        foreach ($manifest->templates as $i => $template) {
            $label = $template->name;
            if ($label === '') {
                $label = sprintf('(template at index %d)', $i);
                $errors[] = sprintf('template at index %d: name must not be empty', $i);
            } elseif (strlen($template->name) > self::MAX_TEMPLATE_NAME_LENGTH) {
                $errors[] = sprintf(
                    'template name exceeds maximum length of %d characters (%d)',
                    self::MAX_TEMPLATE_NAME_LENGTH,
                    strlen($template->name),
                );
            } elseif (isset($templateNames[$template->name])) {
                $errors[] = sprintf('duplicate template name "%s"', $template->name);
            }
            if ($template->name !== '') {
                $templateNames[$template->name] = true;
            }

            if (count($template->scopes) === 0) {
                $errors[] = sprintf('template %s must have at least one scope', $label);
            }

            $refSet = [];
            foreach ($template->scopes as $ref) {
                if ($scopesDefined && !isset($scopeSet[$ref])) {
                    $errors[] = sprintf('template %s references undefined scope "%s"', $label, $ref);
                }
                if (isset($refSet[$ref])) {
                    $errors[] = sprintf('template %s has duplicate scope reference "%s"', $label, $ref);
                }
                $refSet[$ref] = true;
            }
        }

        foreach ($manifest->templates as $i => $template) {
            if ($template->replaces !== '' && isset($templateNames[$template->replaces])) {
                $label = $template->name !== '' ? $template->name : sprintf('(template at index %d)', $i);
                $errors[] = sprintf(
                    'template %s replaces "%s" which exists in the same manifest; replaces must reference an external template',
                    $label,
                    $template->replaces,
                );
            }
        }

        if (count($errors) > self::MAX_VALIDATION_ERRORS) {
            $remaining = count($errors) - self::MAX_VALIDATION_ERRORS;
            $errors = array_slice($errors, 0, self::MAX_VALIDATION_ERRORS);
            $errors[] = sprintf('... and %d more errors', $remaining);
        }

        if ($errors !== []) {
            throw new ManifestValidationException($errors);
        }
    }

    private static function validateServiceCode(string $code): ?string
    {
        if ($code === '') {
            return 'service_code is required';
        }
        if (!preg_match(self::SERVICE_CODE_PATTERN, $code)) {
            return sprintf('service_code "%s" must contain only lowercase letters, numbers, and underscores', $code);
        }

        return null;
    }

    private static function validateScopeName(string $name, string $serviceCode): ?string
    {
        if ($name === '') {
            return 'scope name must not be empty';
        }
        if (strlen($name) > ScopeValidator::MAX_NAME_LENGTH) {
            return sprintf('scope name exceeds maximum length of %d characters (%d)', ScopeValidator::MAX_NAME_LENGTH, strlen($name));
        }
        if ($name !== strtolower($name)) {
            return sprintf('scope name "%s" must be lowercase', $name);
        }
        if (!preg_match(ScopeValidator::NAME_PATTERN, $name)) {
            return sprintf('scope name "%s" must match pattern service:resource:action (2-3 colon-separated lowercase segments)', $name);
        }

        $segments = explode(':', $name);
        if ($segments[0] !== $serviceCode) {
            return sprintf('scope name "%s" must start with service code "%s"', $name, $serviceCode);
        }

        // Wildcard must be the entire segment (e.g. "app*rove" is invalid)
        foreach (array_slice($segments, 1) as $seg) {
            if ($seg !== '*' && str_contains($seg, '*')) {
                return sprintf('scope name "%s" contains embedded wildcard; wildcard (*) must be the entire segment', $name);
            }
        }

        // Wildcard only allowed as the final segment (e.g. "bgc:*:read" is invalid)
        foreach (array_slice($segments, 1, -1) as $seg) {
            if ($seg === '*') {
                return sprintf('scope name "%s" has wildcard in non-final segment; wildcard (*) is only allowed as the final segment', $name);
            }
        }

        return null;
    }
}
