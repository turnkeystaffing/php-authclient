<?php

declare(strict_types=1);

namespace Turnkey\AuthClient\Tests;

use PHPUnit\Framework\TestCase;
use Turnkey\AuthClient\Cache\RedisCache;
use Turnkey\AuthClient\Redis\PrefixedClient;

class RedisCacheTest extends TestCase
{
    private MockRedisClient $mock;
    private RedisCache $cache;

    protected function setUp(): void
    {
        $this->mock = new MockRedisClient();
        $redis = new PrefixedClient($this->mock, prefix: 'test:');
        $this->cache = new RedisCache($redis, keyNamespace: 'introspection:');
    }

    public function testGetSetRoundTrip(): void
    {
        $value = [
            'active' => true,
            'client_id' => 'c1',
            'scope' => 'read write',
            'gty' => 'client_credentials',
            'auth_time' => 1700000000,
        ];

        $this->cache->set('token-hash', $value, 300);
        $result = $this->cache->get('token-hash');

        $this->assertIsArray($result);
        $this->assertTrue($result['active']);
        $this->assertSame('c1', $result['client_id']);
        $this->assertSame('read write', $result['scope']);
        $this->assertSame('client_credentials', $result['gty']);
        $this->assertSame(1700000000, $result['auth_time']);
    }

    public function testGetMissReturnsNull(): void
    {
        $this->assertNull($this->cache->get('nonexistent'));
    }

    public function testDelete(): void
    {
        $this->cache->set('key', ['data' => true], 60);
        $this->assertNotNull($this->cache->get('key'));

        $this->cache->delete('key');
        $this->assertNull($this->cache->get('key'));
    }

    public function testCustomKeyNamespace(): void
    {
        $mock = new MockRedisClient();
        $redis = new PrefixedClient($mock, prefix: 'app:');
        $cache = new RedisCache($redis, keyNamespace: 'custom:');

        $cache->set('abc', ['x' => 1], 60);

        // Key should be: prefix "app:" + namespace "custom:" + key "abc"
        $this->assertArrayHasKey('app:custom:abc', $mock->data);
    }

    public function testDefaultKeyNamespace(): void
    {
        $mock = new MockRedisClient();
        $redis = new PrefixedClient($mock, prefix: 'test:');
        $cache = new RedisCache($redis);

        $cache->set('xyz', ['x' => 1], 60);

        // No namespace, key should be: prefix "test:" + key "xyz"
        $this->assertArrayHasKey('test:xyz', $mock->data);
    }
}