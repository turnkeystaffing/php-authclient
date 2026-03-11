<?php

declare(strict_types=1);

namespace Turnkey\AuthClient;

interface TokenValidatorInterface
{
    /**
     * Validate a bearer token and extract claims.
     *
     * @throws AuthClientError on validation failure
     */
    public function validateToken(string $token): Claims;
}
