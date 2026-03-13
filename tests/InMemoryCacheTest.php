<?php

declare(strict_types=1);

namespace Turnkey\AuthClient\Tests;

use PHPUnit\Framework\TestCase;
use Turnkey\AuthClient\Cache\InMemoryCache;

class InMemoryCacheTest extends TestCase
{
    public function testGetSetDelete(): void
    {
        $cache = new InMemoryCache();
        $value = ['active' => true, 'client_id' => 'c1'];

        $this->assertNull($cache->get('key1'));

        $cache->set('key1', $value, 60);
        $result = $cache->get('key1');

        $this->assertSame($value, $result);

        $cache->delete('key1');
        $this->assertNull($cache->get('key1'));
    }

    public function testExpiredEntryReturnsNull(): void
    {
        $cache = new InMemoryCache();

        // Set with 0 TTL — should expire immediately
        $cache->set('key1', 'data', 0);

        // Sleep briefly to ensure expiration
        usleep(10000); // 10ms

        $this->assertNull($cache->get('key1'));
    }

    public function testMaxSizeEviction(): void
    {
        $cache = new InMemoryCache(maxSize: 2);

        $cache->set('k1', 'first', 10);
        $cache->set('k2', 'second', 20);
        $cache->set('k3', 'third', 30); // should evict k1 (shortest TTL)

        $this->assertNull($cache->get('k1'));
        $this->assertSame('second', $cache->get('k2'));
        $this->assertSame('third', $cache->get('k3'));
    }

    public function testDeleteNonExistentKey(): void
    {
        $cache = new InMemoryCache();
        $cache->delete('nope'); // should not throw
        $this->assertNull($cache->get('nope'));
    }
}