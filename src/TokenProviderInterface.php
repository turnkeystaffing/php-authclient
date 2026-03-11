<?php

declare(strict_types=1);

namespace Turnkey\AuthClient;

interface TokenProviderInterface
{
    /**
     * Obtain a bearer token for outbound API authentication.
     *
     * @throws AuthClientError on failure
     */
    public function getToken(): string;
}
