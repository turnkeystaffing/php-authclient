<?php

declare(strict_types=1);

namespace Turnkey\AuthClient\Tests;

use PHPUnit\Framework\TestCase;
use Turnkey\AuthClient\Cache\InMemoryCache;
use Turnkey\AuthClient\IntrospectionResponse;

class InMemoryCacheTest extends TestCase
{
    public function testGetSetDelete(): void
    {
        $cache = new InMemoryCache();
        $response = new IntrospectionResponse(active: true, clientId: 'c1');

        $this->assertNull($cache->get('key1'));

        $cache->set('key1', $response, 60);
        $result = $cache->get('key1');

        $this->assertNotNull($result);
        $this->assertTrue($result->active);
        $this->assertSame('c1', $result->clientId);

        $cache->delete('key1');
        $this->assertNull($cache->get('key1'));
    }

    public function testExpiredEntryReturnsNull(): void
    {
        $cache = new InMemoryCache();
        $response = new IntrospectionResponse(active: true, clientId: 'c1');

        // Set with 0 TTL — should expire immediately
        $cache->set('key1', $response, 0);

        // Sleep briefly to ensure expiration
        usleep(10000); // 10ms

        $this->assertNull($cache->get('key1'));
    }

    public function testMaxSizeEviction(): void
    {
        $cache = new InMemoryCache(maxSize: 2);

        $r1 = new IntrospectionResponse(active: true, clientId: 'first');
        $r2 = new IntrospectionResponse(active: true, clientId: 'second');
        $r3 = new IntrospectionResponse(active: true, clientId: 'third');

        $cache->set('k1', $r1, 10);
        $cache->set('k2', $r2, 20);
        $cache->set('k3', $r3, 30); // should evict k1 (shortest TTL)

        $this->assertNull($cache->get('k1'));
        $this->assertNotNull($cache->get('k2'));
        $this->assertNotNull($cache->get('k3'));
    }

    public function testDeleteNonExistentKey(): void
    {
        $cache = new InMemoryCache();
        $cache->delete('nope'); // should not throw
        $this->assertNull($cache->get('nope'));
    }
}