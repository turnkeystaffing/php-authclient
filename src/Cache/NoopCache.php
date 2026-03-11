<?php

declare(strict_types=1);

namespace Turnkey\AuthClient\Cache;

use Turnkey\AuthClient\IntrospectionCacheInterface;
use Turnkey\AuthClient\IntrospectionResponse;

class NoopCache implements IntrospectionCacheInterface
{
    public function get(string $key): ?IntrospectionResponse
    {
        return null;
    }

    public function set(string $key, IntrospectionResponse $response, int $ttlSeconds): void
    {
    }

    public function delete(string $key): void
    {
    }
}
