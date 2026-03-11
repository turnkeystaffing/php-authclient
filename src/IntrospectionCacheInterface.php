<?php

declare(strict_types=1);

namespace Turnkey\AuthClient;

interface IntrospectionCacheInterface
{
    public function get(string $key): ?IntrospectionResponse;

    public function set(string $key, IntrospectionResponse $response, int $ttlSeconds): void;

    public function delete(string $key): void;
}
