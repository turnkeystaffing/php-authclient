<?php

declare(strict_types=1);

namespace Turnkey\AuthClient\Tests;

use PHPUnit\Framework\TestCase;
use Turnkey\AuthClient\Redis\PrefixedClient;

class PrefixedClientTest extends TestCase
{
    public function testDefaultPrefix(): void
    {
        $mock = new MockRedisClient();
        $client = new PrefixedClient($mock);

        $this->assertSame('authclient:', $client->getPrefix());
    }

    public function testCustomPrefix(): void
    {
        $mock = new MockRedisClient();
        $client = new PrefixedClient($mock, prefix: 'myapp:');

        $this->assertSame('myapp:', $client->getPrefix());
    }

    public function testGetPrefixesKey(): void
    {
        $mock = new MockRedisClient();
        $client = new PrefixedClient($mock, prefix: 'test:');

        $client->set('foo', 'bar', 60);
        $result = $client->get('foo');

        $this->assertSame('bar', $result);
        $this->assertArrayHasKey('test:foo', $mock->data);
    }

    public function testGetMissReturnsNull(): void
    {
        $mock = new MockRedisClient();
        $client = new PrefixedClient($mock, prefix: 'test:');

        $this->assertNull($client->get('nonexistent'));
    }

    public function testDelPrefixesKeys(): void
    {
        $mock = new MockRedisClient();
        $client = new PrefixedClient($mock, prefix: 'test:');

        $client->set('a', '1', 60);
        $client->set('b', '2', 60);

        $this->assertNotNull($client->get('a'));

        $client->del('a', 'b');

        $this->assertNull($client->get('a'));
        $this->assertNull($client->get('b'));
    }

    public function testDelEmptyKeysNoop(): void
    {
        $mock = new MockRedisClient();
        $client = new PrefixedClient($mock, prefix: 'test:');
        $client->del(); // should not throw
        $this->assertSame(0, $mock->delCallCount);
    }

    public function testSetUsesSetex(): void
    {
        $mock = new MockRedisClient();
        $client = new PrefixedClient($mock, prefix: 'p:');

        $client->set('key', 'val', 120);

        $this->assertSame('val', $mock->data['p:key']['value']);
        $this->assertSame(120, $mock->data['p:key']['ttl']);
    }
}

/**
 * Minimal in-memory Redis mock for testing PrefixedClient.
 */
class MockRedisClient
{
    /** @var array<string, array{value: string, ttl: int}> */
    public array $data = [];
    public int $delCallCount = 0;

    public function get(string $key): ?string
    {
        return $this->data[$key]['value'] ?? null;
    }

    public function setex(string $key, int $ttl, string $value): void
    {
        $this->data[$key] = ['value' => $value, 'ttl' => $ttl];
    }

    public function del(string ...$keys): void
    {
        $this->delCallCount++;
        foreach ($keys as $key) {
            unset($this->data[$key]);
        }
    }
}