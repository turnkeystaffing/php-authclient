<?php

declare(strict_types=1);

namespace Turnkey\AuthClient\Tests;

use PHPUnit\Framework\TestCase;
use Psr\Log\NullLogger;
use Symfony\Component\HttpClient\MockHttpClient;
use Symfony\Component\HttpClient\Response\MockResponse;
use Turnkey\AuthClient\AuthClientError;
use Turnkey\AuthClient\Cache\InMemoryCache;
use Turnkey\AuthClient\Claims;
use Turnkey\AuthClient\IntrospectionClient;
use Turnkey\AuthClient\IntrospectionResponse;
use Turnkey\AuthClient\NoopValidator;
use Turnkey\AuthClient\TokenValidatorInterface;

class IntrospectionClientTest extends TestCase
{
    /** @var array<int, array{method: string, url: string, options: array}> */
    private array $requests = [];

    /**
     * @param MockResponse|MockResponse[] $responses
     */
    private function client(
        MockResponse|array $responses,
        ?InMemoryCache $cache = null,
        int $cacheTtl = 300,
        ?TokenValidatorInterface $fallback = null,
    ): IntrospectionClient {
        $responses = is_array($responses) ? $responses : [$responses];
        $http = new MockHttpClient(function (string $method, string $url, array $options) use (&$responses) {
            $this->requests[] = ['method' => $method, 'url' => $url, 'options' => $options];
            return array_shift($responses) ?? new MockResponse('', ['http_code' => 500]);
        });

        return new IntrospectionClient(
            introspectionEndpoint: 'https://auth.example.com/introspect',
            clientId: 'rs',
            clientSecret: 'secret',
            httpClient: $http,
            logger: new NullLogger(),
            cache: $cache,
            cacheTtlSeconds: $cacheTtl,
            fallbackValidator: $fallback,
        );
    }

    private static function active(array $extra = []): MockResponse
    {
        return new MockResponse(json_encode($extra + [
            'active' => true,
            'client_id' => 'c1',
            'sub' => 'user-1',
            'email' => 'u@example.com',
            'scope' => 'svc:data:read svc:data:write',
            'exp' => time() + 600,
        ]));
    }

    private function assertErrorType(string $type, callable $fn): void
    {
        try {
            $fn();
            $this->fail('expected AuthClientError');
        } catch (AuthClientError $e) {
            $this->assertSame($type, $e->getErrorType());
        }
    }

    public function testValidateTokenMapsClaims(): void
    {
        $claims = $this->client(self::active())->validateToken('tok');

        $this->assertSame('c1', $claims->clientId);
        $this->assertSame('user-1', $claims->userId);
        $this->assertSame('user-1', $claims->subject);
        $this->assertSame('u@example.com', $claims->email);
        $this->assertSame(['svc:data:read', 'svc:data:write'], $claims->scopes);
    }

    public function testRequestIncludesTokenTypeHint(): void
    {
        $this->client(self::active())->introspect('tok');

        parse_str($this->requests[0]['options']['body'], $body);
        $this->assertSame(['token' => 'tok', 'token_type_hint' => 'access_token'], $body);
    }

    public function testOversizedTokenRejectedWithoutRequest(): void
    {
        $client = $this->client(self::active());
        $this->assertErrorType(AuthClientError::TOKEN_OVERSIZED, fn() => $client->introspect(str_repeat('a', 4097)));
        $this->assertCount(0, $this->requests);
    }

    public function testNon200IsRejected(): void
    {
        $client = $this->client(new MockResponse('{"active":true}', ['http_code' => 201]));
        $this->assertErrorType(AuthClientError::INTROSPECTION_REJECTED, fn() => $client->introspect('tok'));
    }

    public function testEmptyBodyIsParseError(): void
    {
        $client = $this->client(new MockResponse(''));
        $this->assertErrorType(AuthClientError::INTROSPECTION_PARSE, fn() => $client->introspect('tok'));
    }

    public function testInactiveTokenRejected(): void
    {
        $client = $this->client(new MockResponse('{"active":false}'));
        $this->assertErrorType(AuthClientError::TOKEN_INACTIVE, fn() => $client->validateToken('tok'));
    }

    public function testCachesActiveResponseUnderPrefixedKey(): void
    {
        $cache = new InMemoryCache();
        $client = $this->client([self::active()], $cache);

        $client->introspect('tok');
        $client->introspect('tok');

        $this->assertCount(1, $this->requests);
        $this->assertInstanceOf(IntrospectionResponse::class, $cache->get('introspect:' . hash('sha256', 'tok')));
    }

    public function testExpiredCacheEntryIsRefetched(): void
    {
        $cache = new InMemoryCache();
        $key = 'introspect:' . hash('sha256', 'tok');
        $cache->set($key, new IntrospectionResponse(active: true, clientId: 'stale', exp: time() - 1), 60);

        $response = $this->client(self::active(), $cache)->introspect('tok');

        $this->assertSame('c1', $response->clientId);
        $this->assertCount(1, $this->requests);
    }

    public function testInactiveResponseDeletesCacheEntry(): void
    {
        $cache = new InMemoryCache();
        $key = 'introspect:' . hash('sha256', 'tok');
        $cache->set($key, new IntrospectionResponse(active: false), 60);

        $this->client(new MockResponse('{"active":false}'), $cache)->introspect('tok');

        $this->assertNull($cache->get($key));
    }

    public function testZeroTtlUsesRemainingLifetime(): void
    {
        $cache = new InMemoryCache();
        $client = $this->client([self::active(['exp' => time() + 5])], $cache, cacheTtl: 0);

        $client->introspect('tok');

        $this->assertNotNull($cache->get('introspect:' . hash('sha256', 'tok')));
    }

    public function testZeroTtlWithoutExpDoesNotCache(): void
    {
        $cache = new InMemoryCache();
        $client = $this->client([new MockResponse('{"active":true,"client_id":"c1"}')], $cache, cacheTtl: 0);

        $client->introspect('tok');

        $this->assertNull($cache->get('introspect:' . hash('sha256', 'tok')));
    }

    public function testFallbackOnNetworkErrorReturnsFallbackClaims(): void
    {
        $fallbackClaims = new Claims(clientId: 'jwks', scopes: ['svc:data:read'], userId: 'u1', email: 'e@x.com');
        $client = $this->client(
            new MockResponse('', ['error' => 'Connection refused']),
            fallback: new NoopValidator($fallbackClaims),
        );

        $claims = $client->validateToken('tok');

        $this->assertSame('jwks', $claims->clientId);
        $this->assertSame('e@x.com', $claims->email, 'fallback claims are returned without lossy conversion');
    }

    public function testNoFallbackOnHttpError(): void
    {
        $client = $this->client(
            new MockResponse('', ['http_code' => 503]),
            fallback: new NoopValidator(new Claims(clientId: 'jwks')),
        );
        $this->assertErrorType(AuthClientError::INTROSPECTION_REJECTED, fn() => $client->validateToken('tok'));
    }

    public function testIntrospectDoesNotFallBack(): void
    {
        $client = $this->client(
            new MockResponse('', ['error' => 'Connection refused']),
            fallback: new NoopValidator(new Claims(clientId: 'jwks')),
        );
        $this->assertErrorType(AuthClientError::INTROSPECTION_FAILED, fn() => $client->introspect('tok'));
    }

    public function testConstructorValidation(): void
    {
        $http = new MockHttpClient();
        foreach ([['', 'c', 's'], ['https://a/i', '', 's'], ['https://a/i', 'c', '']] as [$url, $id, $secret]) {
            try {
                new IntrospectionClient($url, $id, $secret, $http, new NullLogger());
                $this->fail('expected InvalidArgumentException');
            } catch (\InvalidArgumentException) {
                $this->addToAssertionCount(1);
            }
        }
    }
}
