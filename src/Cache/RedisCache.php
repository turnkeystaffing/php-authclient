<?php

declare(strict_types=1);

namespace Turnkey\AuthClient\Cache;

use Turnkey\AuthClient\CacheInterface;
use Turnkey\AuthClient\Redis\RedisClientInterface;

/**
 * Redis-backed cache using RedisClientInterface.
 *
 * Handles JSON serialization internally. Key prefixing is handled
 * by the underlying PrefixedClient; this class only adds its own
 * configurable namespace (e.g. "myapp:" + "introspection:" + key).
 */
class RedisCache implements CacheInterface
{
    private readonly string $keyNamespace;

    public function __construct(
        private readonly RedisClientInterface $redis,
        string $keyNamespace = '',
    ) {
        $this->keyNamespace = $keyNamespace;
    }

    public function get(string $key): mixed
    {
        $data = $this->redis->get($this->keyNamespace . $key);
        if ($data === null) {
            return null;
        }

        return json_decode($data, true);
    }

    public function set(string $key, mixed $value, int $ttlSeconds): void
    {
        $data = json_encode($value, JSON_THROW_ON_ERROR);
        $this->redis->set($this->keyNamespace . $key, $data, $ttlSeconds);
    }

    public function delete(string $key): void
    {
        $this->redis->del($this->keyNamespace . $key);
    }
}