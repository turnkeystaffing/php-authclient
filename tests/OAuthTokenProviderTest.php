<?php

declare(strict_types=1);

namespace Turnkey\AuthClient\Tests;

use PHPUnit\Framework\TestCase;
use Psr\Log\NullLogger;
use Symfony\Contracts\HttpClient\HttpClientInterface;
use Symfony\Contracts\HttpClient\ResponseInterface;
use Turnkey\AuthClient\AuthClientError;
use Turnkey\AuthClient\Cache\InMemoryCache;
use Turnkey\AuthClient\OAuthTokenProvider;

class OAuthTokenProviderTest extends TestCase
{
    private NullLogger $logger;

    protected function setUp(): void
    {
        $this->logger = new NullLogger();
    }

    // --- Basic token fetch ---

    public function testGetTokenFetchesAndReturns(): void
    {
        $httpClient = $this->mockHttpClient(
            '{"access_token":"tok-abc","token_type":"Bearer","expires_in":3600}',
        );

        $provider = new OAuthTokenProvider(
            tokenEndpoint: 'https://auth.example.com/token',
            clientId: 'client1',
            clientSecret: 'secret1',
            httpClient: $httpClient,
            logger: $this->logger,
        );

        $this->assertSame('tok-abc', $provider->getToken());
    }

    public function testGetTokenReturnsCachedOnSecondCall(): void
    {
        $callCount = 0;
        $httpClient = $this->mockHttpClient(
            '{"access_token":"tok-abc","token_type":"Bearer","expires_in":3600}',
            callCount: $callCount,
        );

        $provider = new OAuthTokenProvider(
            tokenEndpoint: 'https://auth.example.com/token',
            clientId: 'client1',
            clientSecret: 'secret1',
            httpClient: $httpClient,
            logger: $this->logger,
        );

        $provider->getToken();
        $provider->getToken();

        $this->assertSame(1, $callCount);
    }

    // --- Closed provider ---

    public function testGetTokenAfterCloseThrows(): void
    {
        $httpClient = $this->mockHttpClient(
            '{"access_token":"tok","token_type":"Bearer","expires_in":3600}',
        );

        $provider = new OAuthTokenProvider(
            tokenEndpoint: 'https://auth.example.com/token',
            clientId: 'client1',
            clientSecret: 'secret1',
            httpClient: $httpClient,
            logger: $this->logger,
        );

        $provider->getToken();
        $provider->close();

        $this->expectException(AuthClientError::class);
        $provider->getToken();
    }

    // --- Validation ---

    public function testRejectsNonBearerTokenType(): void
    {
        $httpClient = $this->mockHttpClient(
            '{"access_token":"tok","token_type":"mac","expires_in":3600}',
        );

        $provider = new OAuthTokenProvider(
            tokenEndpoint: 'https://auth.example.com/token',
            clientId: 'client1',
            clientSecret: 'secret1',
            httpClient: $httpClient,
            logger: $this->logger,
        );

        $this->expectException(AuthClientError::class);
        $provider->getToken();
    }

    public function testRejectsZeroExpiresIn(): void
    {
        $httpClient = $this->mockHttpClient(
            '{"access_token":"tok","token_type":"Bearer","expires_in":0}',
        );

        $provider = new OAuthTokenProvider(
            tokenEndpoint: 'https://auth.example.com/token',
            clientId: 'client1',
            clientSecret: 'secret1',
            httpClient: $httpClient,
            logger: $this->logger,
        );

        $this->expectException(AuthClientError::class);
        $provider->getToken();
    }

    public function testRejectsExcessiveExpiresIn(): void
    {
        $httpClient = $this->mockHttpClient(
            '{"access_token":"tok","token_type":"Bearer","expires_in":99999999}',
        );

        $provider = new OAuthTokenProvider(
            tokenEndpoint: 'https://auth.example.com/token',
            clientId: 'client1',
            clientSecret: 'secret1',
            httpClient: $httpClient,
            logger: $this->logger,
        );

        $this->expectException(AuthClientError::class);
        $provider->getToken();
    }

    // --- HTTP errors ---

    public function testHttpErrorThrowsAuthClientError(): void
    {
        $httpClient = $this->mockHttpClient('', statusCode: 500);

        $provider = new OAuthTokenProvider(
            tokenEndpoint: 'https://auth.example.com/token',
            clientId: 'client1',
            clientSecret: 'secret1',
            httpClient: $httpClient,
            logger: $this->logger,
        );

        $this->expectException(AuthClientError::class);
        $provider->getToken();
    }

    // --- Scopes sent in request ---

    public function testScopesIncludedInRequest(): void
    {
        $capturedBody = null;
        $response = $this->createStub(ResponseInterface::class);
        $response->method('getStatusCode')->willReturn(200);
        $response->method('getContent')->willReturn(
            '{"access_token":"tok","token_type":"Bearer","expires_in":3600}',
        );

        $httpClient = $this->createMock(HttpClientInterface::class);
        $httpClient->expects($this->once())
            ->method('request')
            ->with(
                'POST',
                $this->anything(),
                $this->callback(function (array $options) use (&$capturedBody) {
                    $capturedBody = $options['body'] ?? '';
                    return true;
                }),
            )
            ->willReturn($response);

        $provider = new OAuthTokenProvider(
            tokenEndpoint: 'https://auth.example.com/token',
            clientId: 'client1',
            clientSecret: 'secret1',
            httpClient: $httpClient,
            logger: $this->logger,
            scopes: ['api.read', 'api.write'],
        );

        $provider->getToken();

        parse_str($capturedBody, $params);
        $this->assertSame('api.read api.write', $params['scope']);
    }

    // --- Persistent cache ---

    public function testPersistentCacheStoresToken(): void
    {
        $cache = new InMemoryCache();
        $httpClient = $this->mockHttpClient(
            '{"access_token":"tok-persisted","token_type":"Bearer","expires_in":3600}',
        );

        $provider = new OAuthTokenProvider(
            tokenEndpoint: 'https://auth.example.com/token',
            clientId: 'client1',
            clientSecret: 'secret1',
            httpClient: $httpClient,
            logger: $this->logger,
            cache: $cache,
        );

        $provider->getToken();

        // A new provider with same config should load from cache without HTTP call
        $callCount = 0;
        $httpClient2 = $this->mockHttpClient(
            '{"access_token":"should-not-use","token_type":"Bearer","expires_in":3600}',
            callCount: $callCount,
        );

        $provider2 = new OAuthTokenProvider(
            tokenEndpoint: 'https://auth.example.com/token',
            clientId: 'client1',
            clientSecret: 'secret1',
            httpClient: $httpClient2,
            logger: $this->logger,
            cache: $cache,
        );

        $this->assertSame('tok-persisted', $provider2->getToken());
        $this->assertSame(0, $callCount);
    }

    // --- Cache key isolation ---

    public function testDifferentClientIdGetsSeparateCacheKey(): void
    {
        $cache = new InMemoryCache();

        $httpClient1 = $this->mockHttpClient(
            '{"access_token":"tok-client1","token_type":"Bearer","expires_in":3600}',
        );
        $provider1 = new OAuthTokenProvider(
            tokenEndpoint: 'https://auth.example.com/token',
            clientId: 'client1',
            clientSecret: 'secret1',
            httpClient: $httpClient1,
            logger: $this->logger,
            cache: $cache,
        );
        $provider1->getToken();

        $httpClient2 = $this->mockHttpClient(
            '{"access_token":"tok-client2","token_type":"Bearer","expires_in":3600}',
        );
        $provider2 = new OAuthTokenProvider(
            tokenEndpoint: 'https://auth.example.com/token',
            clientId: 'client2',
            clientSecret: 'secret2',
            httpClient: $httpClient2,
            logger: $this->logger,
            cache: $cache,
        );

        // client2 should NOT get client1's cached token
        $this->assertSame('tok-client2', $provider2->getToken());
    }

    public function testDifferentScopesGetSeparateCacheKey(): void
    {
        $cache = new InMemoryCache();

        $httpClient1 = $this->mockHttpClient(
            '{"access_token":"tok-read","token_type":"Bearer","expires_in":3600}',
        );
        $provider1 = new OAuthTokenProvider(
            tokenEndpoint: 'https://auth.example.com/token',
            clientId: 'client1',
            clientSecret: 'secret1',
            httpClient: $httpClient1,
            logger: $this->logger,
            scopes: ['api.read'],
            cache: $cache,
        );
        $provider1->getToken();

        $httpClient2 = $this->mockHttpClient(
            '{"access_token":"tok-write","token_type":"Bearer","expires_in":3600}',
        );
        $provider2 = new OAuthTokenProvider(
            tokenEndpoint: 'https://auth.example.com/token',
            clientId: 'client1',
            clientSecret: 'secret1',
            httpClient: $httpClient2,
            logger: $this->logger,
            scopes: ['api.write'],
            cache: $cache,
        );

        // Different scopes should NOT share cache
        $this->assertSame('tok-write', $provider2->getToken());
    }

    public function testSameScopesDifferentOrderShareCacheKey(): void
    {
        $cache = new InMemoryCache();

        $httpClient1 = $this->mockHttpClient(
            '{"access_token":"tok-original","token_type":"Bearer","expires_in":3600}',
        );
        $provider1 = new OAuthTokenProvider(
            tokenEndpoint: 'https://auth.example.com/token',
            clientId: 'client1',
            clientSecret: 'secret1',
            httpClient: $httpClient1,
            logger: $this->logger,
            scopes: ['api.write', 'api.read'],
            cache: $cache,
        );
        $provider1->getToken();

        $callCount = 0;
        $httpClient2 = $this->mockHttpClient(
            '{"access_token":"tok-unused","token_type":"Bearer","expires_in":3600}',
            callCount: $callCount,
        );
        $provider2 = new OAuthTokenProvider(
            tokenEndpoint: 'https://auth.example.com/token',
            clientId: 'client1',
            clientSecret: 'secret1',
            httpClient: $httpClient2,
            logger: $this->logger,
            scopes: ['api.read', 'api.write'],
            cache: $cache,
        );

        // Same scopes in different order should share cache
        $this->assertSame('tok-original', $provider2->getToken());
        $this->assertSame(0, $callCount);
    }

    // --- Helpers ---

    private function mockHttpClient(string $responseBody, int $statusCode = 200, int &$callCount = null): HttpClientInterface
    {
        $response = $this->createStub(ResponseInterface::class);
        $response->method('getStatusCode')->willReturn($statusCode);
        $response->method('getContent')->willReturn($responseBody);

        $httpClient = $this->createStub(HttpClientInterface::class);
        $httpClient->method('request')->willReturnCallback(
            function () use ($response, &$callCount) {
                if ($callCount !== null) {
                    $callCount++;
                }
                return $response;
            },
        );

        return $httpClient;
    }
}