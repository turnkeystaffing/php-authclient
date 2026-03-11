<?php

declare(strict_types=1);

namespace Turnkey\AuthClient;

/**
 * Development/testing validator that returns preconfigured claims for any token.
 */
class NoopValidator implements TokenValidatorInterface
{
    public function __construct(
        private readonly Claims $defaultClaims,
    ) {
    }

    public function validateToken(string $token): Claims
    {
        return $this->defaultClaims->deepCopy();
    }
}
