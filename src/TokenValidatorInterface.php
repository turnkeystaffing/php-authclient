<?php

declare(strict_types=1);

namespace Turnkey\AuthClient;

interface TokenValidatorInterface
{
    /**
     * Maximum allowed length of a Bearer token string. Tokens exceeding this limit
     * are rejected before parsing or network calls to prevent DoS.
     */
    public const MAX_BEARER_TOKEN_LENGTH = 4096;

    /**
     * Validate a bearer token and extract claims.
     *
     * @throws AuthClientError on validation failure
     */
    public function validateToken(string $token): Claims;
}
