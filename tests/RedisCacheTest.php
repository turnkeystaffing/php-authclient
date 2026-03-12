<?php

declare(strict_types=1);

namespace Turnkey\AuthClient\Tests;

use PHPUnit\Framework\TestCase;
use Turnkey\AuthClient\Cache\RedisCache;
use Turnkey\AuthClient\IntrospectionResponse;
use Turnkey\AuthClient\Redis\PrefixedClient;

class RedisCacheTest extends TestCase
{
    private MockRedisClient $mock;
    private RedisCache $cache;

    protected function setUp(): void
    {
        $this->mock = new MockRedisClient();
        $redis = new PrefixedClient($this->mock, prefix: 'test:');
        $this->cache = new RedisCache($redis);
    }

    public function testGetSetRoundTrip(): void
    {
        $response = new IntrospectionResponse(
            active: true,
            clientId: 'c1',
            scope: 'read write',
            grantType: 'client_credentials',
            authTime: 1700000000,
        );

        $this->cache->set('token-hash', $response, 300);
        $result = $this->cache->get('token-hash');

        $this->assertNotNull($result);
        $this->assertTrue($result->active);
        $this->assertSame('c1', $result->clientId);
        $this->assertSame('read write', $result->scope);
        $this->assertSame('client_credentials', $result->grantType);
        $this->assertSame(1700000000, $result->authTime);
    }

    public function testGetMissReturnsNull(): void
    {
        $this->assertNull($this->cache->get('nonexistent'));
    }

    public function testDelete(): void
    {
        $response = new IntrospectionResponse(active: true, clientId: 'c1');

        $this->cache->set('key', $response, 60);
        $this->assertNotNull($this->cache->get('key'));

        $this->cache->delete('key');
        $this->assertNull($this->cache->get('key'));
    }

    public function testCustomKeyNamespace(): void
    {
        $mock = new MockRedisClient();
        $redis = new PrefixedClient($mock, prefix: 'app:');
        $cache = new RedisCache($redis, keyNamespace: 'custom:');

        $response = new IntrospectionResponse(active: true, clientId: 'c1');
        $cache->set('abc', $response, 60);

        // Key should be: prefix "app:" + namespace "custom:" + key "abc"
        $this->assertArrayHasKey('app:custom:abc', $mock->data);
    }

    public function testDefaultKeyNamespace(): void
    {
        $response = new IntrospectionResponse(active: true, clientId: 'c1');
        $this->cache->set('xyz', $response, 60);

        // Key should be: prefix "test:" + default namespace "introspection:" + key "xyz"
        $this->assertArrayHasKey('test:introspection:xyz', $this->mock->data);
    }
}