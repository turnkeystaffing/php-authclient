<?php

declare(strict_types=1);

namespace Turnkey\AuthClient;

/**
 * Simple cache interface with TTL support.
 * Used by both IntrospectionClient and OAuthTokenProvider.
 *
 * InMemoryCache stores values as-is. RedisCache handles serialization internally.
 */
interface CacheInterface
{
    public function get(string $key): mixed;

    public function set(string $key, mixed $value, int $ttlSeconds): void;

    public function delete(string $key): void;
}