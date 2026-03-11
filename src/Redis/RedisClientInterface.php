<?php

declare(strict_types=1);

namespace Turnkey\AuthClient\Redis;

/**
 * Minimal Redis client interface matching go-redis RedisClient.
 */
interface RedisClientInterface
{
    public function get(string $key): ?string;

    public function set(string $key, string $value, int $ttlSeconds): void;

    public function del(string ...$keys): void;

    public function getPrefix(): string;
}
