<?php

declare(strict_types=1);

namespace Turnkey\AuthClient\Redis;

/**
 * Redis client wrapper that automatically prefixes all keys.
 *
 * Mirrors the go-redis PrefixedClient pattern: composition over inheritance,
 * transparent key prefixing, configurable prefix with sensible default.
 *
 * Works with any object implementing get/set/del/setex (Predis\Client, Redis extension, etc).
 */
class PrefixedClient implements RedisClientInterface
{
    private const DEFAULT_PREFIX = 'authclient:';

    private readonly string $prefix;

    /**
     * @param object $client Underlying Redis client (Predis\Client or \Redis)
     * @param string $prefix Key prefix. Empty string uses default "authclient:".
     */
    public function __construct(
        private readonly object $client,
        string $prefix = '',
    ) {
        $this->prefix = $prefix !== '' ? $prefix : self::DEFAULT_PREFIX;
    }

    public function get(string $key): ?string
    {
        $result = $this->client->get($this->prefixKey($key));

        if ($result === null || $result === false) {
            return null;
        }

        return (string) $result;
    }

    public function set(string $key, string $value, int $ttlSeconds): void
    {
        $prefixed = $this->prefixKey($key);

        // Support both Predis (setex) and phpredis (\Redis::setex)
        if ($this->client instanceof \Redis) {
            $this->client->set($prefixed, $value, ['EX' => $ttlSeconds]);
        } else {
            // Predis\ClientInterface and anything else that has SETEX (magic or real)
            $this->client->setex($prefixed, $ttlSeconds, $value);
        }
    }

    public function del(string ...$keys): void
    {
        if (empty($keys)) {
            return;
        }

        $this->client->del(...$this->prefixKeys($keys));
    }

    public function getPrefix(): string
    {
        return $this->prefix;
    }

    private function prefixKey(string $key): string
    {
        return $this->prefix . $key;
    }

    /**
     * @param string[] $keys
     * @return string[]
     */
    private function prefixKeys(array $keys): array
    {
        return array_map(fn(string $key) => $this->prefixKey($key), $keys);
    }
}
