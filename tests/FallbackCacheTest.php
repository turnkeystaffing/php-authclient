<?php

declare(strict_types=1);

namespace Turnkey\AuthClient\Tests;

use PHPUnit\Framework\TestCase;
use Turnkey\AuthClient\Cache\FallbackCache;
use Turnkey\AuthClient\Cache\InMemoryCache;
use Turnkey\AuthClient\CacheInterface;

class FallbackCacheTest extends TestCase
{
    public function testUsePrimaryWhenAvailable(): void
    {
        $primary = new InMemoryCache();
        $fallback = new InMemoryCache();
        $cache = new FallbackCache($primary, $fallback);

        $cache->set('k', 'v', 60);

        $this->assertSame('v', $primary->get('k'));
        $this->assertNull($fallback->get('k'));
        $this->assertSame('v', $cache->get('k'));
    }

    public function testFallsBackOnPrimaryGetFailure(): void
    {
        $primary = new FailingCache();
        $fallback = new InMemoryCache();
        $cache = new FallbackCache($primary, $fallback);

        $fallback->set('k', 'cached', 60);

        $this->assertSame('cached', $cache->get('k'));
    }

    public function testFallsBackOnPrimarySetFailure(): void
    {
        $primary = new FailingCache();
        $fallback = new InMemoryCache();
        $cache = new FallbackCache($primary, $fallback);

        $cache->set('k', 'v', 60);

        $this->assertSame('v', $fallback->get('k'));
    }

    public function testFallsBackOnPrimaryDeleteFailure(): void
    {
        $primary = new FailingCache();
        $fallback = new InMemoryCache();
        $fallback->set('k', 'v', 60);
        $cache = new FallbackCache($primary, $fallback);

        $cache->delete('k');

        $this->assertNull($fallback->get('k'));
    }

    public function testCooldownSkipsPrimaryAfterFailure(): void
    {
        $primary = new CountingFailingCache();
        $fallback = new InMemoryCache();
        $cache = new FallbackCache($primary, $fallback, cooldownSeconds: 60);

        // First call: tries primary, fails, falls back
        $cache->get('k');
        $this->assertSame(1, $primary->getAttempts);

        // Subsequent calls within cooldown: skip primary entirely
        $cache->get('k');
        $cache->get('k');
        $this->assertSame(1, $primary->getAttempts);
    }

    public function testCooldownZeroRetiesEveryTime(): void
    {
        $primary = new CountingFailingCache();
        $fallback = new InMemoryCache();
        $cache = new FallbackCache($primary, $fallback, cooldownSeconds: 0);

        $cache->get('a');
        $cache->get('b');
        $cache->get('c');

        $this->assertSame(3, $primary->getAttempts);
    }

    public function testPrimaryRecoveryAfterCooldown(): void
    {
        $togglable = new TogglableCache();
        $fallback = new InMemoryCache();

        // Use reflection to manually expire the cooldown
        $cache = new FallbackCache($togglable, $fallback, cooldownSeconds: 0);

        // Fail first
        $togglable->shouldFail = true;
        $cache->set('k', 'fallback-val', 60);
        $this->assertSame('fallback-val', $fallback->get('k'));

        // Recover
        $togglable->shouldFail = false;
        $cache->set('k2', 'primary-val', 60);
        $this->assertSame('primary-val', $togglable->get('k2'));
    }
}

/** @internal */
class FailingCache implements CacheInterface
{
    public function get(string $key): mixed
    {
        throw new \RuntimeException('Redis unavailable');
    }

    public function set(string $key, mixed $value, int $ttlSeconds): void
    {
        throw new \RuntimeException('Redis unavailable');
    }

    public function delete(string $key): void
    {
        throw new \RuntimeException('Redis unavailable');
    }
}

/** @internal */
class CountingFailingCache implements CacheInterface
{
    public int $getAttempts = 0;

    public function get(string $key): mixed
    {
        $this->getAttempts++;
        throw new \RuntimeException('Redis unavailable');
    }

    public function set(string $key, mixed $value, int $ttlSeconds): void
    {
        throw new \RuntimeException('Redis unavailable');
    }

    public function delete(string $key): void
    {
        throw new \RuntimeException('Redis unavailable');
    }
}

/** @internal */
class TogglableCache implements CacheInterface
{
    public bool $shouldFail = false;
    private array $store = [];

    public function get(string $key): mixed
    {
        if ($this->shouldFail) {
            throw new \RuntimeException('Redis unavailable');
        }
        return $this->store[$key] ?? null;
    }

    public function set(string $key, mixed $value, int $ttlSeconds): void
    {
        if ($this->shouldFail) {
            throw new \RuntimeException('Redis unavailable');
        }
        $this->store[$key] = $value;
    }

    public function delete(string $key): void
    {
        if ($this->shouldFail) {
            throw new \RuntimeException('Redis unavailable');
        }
        unset($this->store[$key]);
    }
}