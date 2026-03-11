<?php

declare(strict_types=1);

namespace Turnkey\AuthClient;

interface IntrospectorInterface
{
    /**
     * Introspect a token via RFC 7662.
     *
     * @throws AuthClientError on failure
     */
    public function introspect(string $token): IntrospectionResponse;
}
