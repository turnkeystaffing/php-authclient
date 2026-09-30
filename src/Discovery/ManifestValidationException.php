<?php

declare(strict_types=1);

namespace Turnkey\AuthClient\Discovery;

/**
 * Collects all validation issues found in a scope manifest.
 */
class ManifestValidationException extends ManifestException
{
    /**
     * @param string[] $errors
     */
    public function __construct(private readonly array $errors)
    {
        parent::__construct('manifest validation failed: ' . implode('; ', $errors));
    }

    /**
     * @return string[]
     */
    public function getErrors(): array
    {
        return $this->errors;
    }
}
