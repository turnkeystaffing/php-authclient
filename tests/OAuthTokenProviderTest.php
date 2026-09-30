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

    // --- go-authclient parity ---

    private function provider(HttpClientInterface $httpClient, array $scopes = [], ?\Psr\Log\LoggerInterface $logger = null): OAuthTokenProvider
    {
        return new OAuthTokenProvider(
            tokenEndpoint: 'https://auth.example.com/token',
            clientId: 'client1',
            clientSecret: 'secret1',
            httpClient: $httpClient,
            logger: $logger ?? $this->logger,
            scopes: $scopes,
        );
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('invalidConfigProvider')]
    public function testInvalidConfigRejected(string $endpoint, string $clientId, string $secret, string $message): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage($message);
        new OAuthTokenProvider($endpoint, $clientId, $secret, $this->mockHttpClient('{}'), $this->logger);
    }

    public static function invalidConfigProvider(): iterable
    {
        yield 'empty client id' => ['https://a.com/token', '', 's', 'client ID is required'];
        yield 'empty secret' => ['https://a.com/token', 'c', '', 'client secret is required'];
        yield 'empty url' => ['', 'c', 's', 'token URL is required'];
        yield 'bad scheme' => ['ftp://a.com/token', 'c', 's', 'scheme must be http or https'];
        yield 'no host' => ['https:/token', 'c', 's', 'must include a host'];
        yield 'unparseable' => ['https:///token', 'c', 's', 'invalid token URL'];
    }

    public function testPlaintextHttpWarnsWithSanitizedUrl(): void
    {
        $logger = $this->createMock(\Psr\Log\LoggerInterface::class);
        $logger->expects($this->once())->method('warning')->with(
            $this->stringContains('plaintext HTTP'),
            ['token_url' => 'http://auth.local:8080/token'],
        );
        new OAuthTokenProvider('http://user:pw@auth.local:8080/token?x=1#f', 'c', 's', $this->mockHttpClient('{}'), $logger);
    }

    public function testEmptyAccessTokenRejected(): void
    {
        $this->expectException(AuthClientError::class);
        $this->expectExceptionMessage('empty access_token');
        $this->provider($this->mockHttpClient('{"access_token":"","token_type":"Bearer","expires_in":60}'))->getToken();
    }

    public function testNon200StatusRejected(): void
    {
        $this->expectException(AuthClientError::class);
        $this->expectExceptionMessage('status 201');
        $this->provider($this->mockHttpClient('{"access_token":"t","token_type":"Bearer","expires_in":60}', 201))->getToken();
    }

    public function testTokenTypeNotEchoed(): void
    {
        try {
            $this->provider($this->mockHttpClient('{"access_token":"t","token_type":"<script>","expires_in":60}'))->getToken();
            $this->fail('expected AuthClientError');
        } catch (AuthClientError $e) {
            $this->assertStringNotContainsString('<script>', $e->getMessage());
            $this->assertStringContainsString('expected Bearer', $e->getMessage());
        }
    }

    public function testSendsAcceptHeader(): void
    {
        $response = $this->createStub(ResponseInterface::class);
        $response->method('getStatusCode')->willReturn(200);
        $response->method('getContent')->willReturn('{"access_token":"t","token_type":"Bearer","expires_in":60}');

        $httpClient = $this->createMock(HttpClientInterface::class);
        $httpClient->expects($this->once())->method('request')->with(
            'POST',
            'https://auth.example.com/token',
            $this->callback(fn(array $o) => ($o['headers']['Accept'] ?? null) === 'application/json'),
        )->willReturn($response);

        $this->provider($httpClient)->getToken();
    }

    public function testGrantedScopeMismatchWarns(): void
    {
        $logger = $this->createMock(\Psr\Log\LoggerInterface::class);
        $logger->expects($this->once())->method('warning')
            ->with($this->stringContains('Granted scope differs'), $this->anything());

        $this->provider(
            $this->mockHttpClient('{"access_token":"t","token_type":"Bearer","expires_in":60,"scope":"a:read"}'),
            ['a:read', 'a:write'],
            $logger,
        )->getToken();
    }

    public function testGrantedScopeSameSetDifferentOrderDoesNotWarn(): void
    {
        $logger = $this->createMock(\Psr\Log\LoggerInterface::class);
        $logger->expects($this->never())->method('warning');

        $this->provider(
            $this->mockHttpClient('{"access_token":"t","token_type":"Bearer","expires_in":60,"scope":"a:write a:read"}'),
            ['a:read', 'a:write'],
            $logger,
        )->getToken();
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