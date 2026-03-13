<?php

declare(strict_types=1);

namespace Turnkey\AuthClient\Cache;

use Turnkey\AuthClient\CacheInterface;

class NoopCache implements CacheInterface
{
    public function get(string $key): mixed
    {
        return null;
    }

    public function set(string $key, mixed $value, int $ttlSeconds): void
    {
    }

    public function delete(string $key): void
    {
    }
}
