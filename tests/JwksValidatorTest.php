<?php

declare(strict_types=1);

namespace Turnkey\AuthClient\Tests;

use PHPUnit\Framework\TestCase;
use Turnkey\AuthClient\AuthClientError;
use Turnkey\AuthClient\JwksProvider;
use Turnkey\AuthClient\JwksValidator;
use Psr\Log\NullLogger;

class JwksValidatorTest extends TestCase
{
    public function testEmptyAudienceRejected(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('audience is required');

        $provider = $this->createStub(JwksProvider::class);
        new JwksValidator($provider, 'https://issuer.com', '', new NullLogger());
    }

    public function testOversizedTokenRejected(): void
    {
        $provider = $this->createStub(JwksProvider::class);
        $validator = new JwksValidator($provider, 'https://issuer.com', 'api', new NullLogger());

        $this->expectException(AuthClientError::class);

        try {
            $validator->validateToken(str_repeat('a', 4097));
        } catch (AuthClientError $e) {
            $this->assertSame(AuthClientError::TOKEN_OVERSIZED, $e->getErrorType());
            throw $e;
        }
    }

    public function testMalformedTokenRejected(): void
    {
        $provider = $this->createStub(JwksProvider::class);
        $provider->method('getKeys')->willReturn(['key1' => 'dummy']);
        $validator = new JwksValidator($provider, 'https://issuer.com', 'api', new NullLogger());

        $this->expectException(AuthClientError::class);

        try {
            $validator->validateToken('not-a-jwt');
        } catch (AuthClientError $e) {
            $this->assertSame(AuthClientError::TOKEN_MALFORMED, $e->getErrorType());
            throw $e;
        }
    }

    public function testNoKeysAvailable(): void
    {
        $provider = $this->createStub(JwksProvider::class);
        $provider->method('getKeys')->willReturn([]);
        $validator = new JwksValidator($provider, 'https://issuer.com', 'api', new NullLogger());

        $this->expectException(AuthClientError::class);

        try {
            $validator->validateToken('a.b.c');
        } catch (AuthClientError $e) {
            $this->assertSame(AuthClientError::TOKEN_UNVERIFIABLE, $e->getErrorType());
            throw $e;
        }
    }

    public function testHmacAlgorithmRejected(): void
    {
        $provider = $this->createStub(JwksProvider::class);
        $provider->method('getKeys')->willReturn(['key1' => 'dummy']);
        $validator = new JwksValidator($provider, 'https://issuer.com', 'api', new NullLogger());

        // Create a token header with HS256
        $header = base64_encode(json_encode(['alg' => 'HS256', 'typ' => 'JWT']));
        $header = rtrim(strtr($header, '+/', '-_'), '=');
        $payload = base64_encode(json_encode(['sub' => '1']));
        $payload = rtrim(strtr($payload, '+/', '-_'), '=');

        $this->expectException(AuthClientError::class);

        try {
            $validator->validateToken("{$header}.{$payload}.signature");
        } catch (AuthClientError $e) {
            $this->assertSame(AuthClientError::ALGORITHM_NOT_ALLOWED, $e->getErrorType());
            $this->assertStringContainsString('HS256', $e->getMessage());
            throw $e;
        }
    }

    public function testNoneAlgorithmRejected(): void
    {
        $provider = $this->createStub(JwksProvider::class);
        $provider->method('getKeys')->willReturn(['key1' => 'dummy']);
        $validator = new JwksValidator($provider, 'https://issuer.com', 'api', new NullLogger());

        $header = base64_encode(json_encode(['alg' => 'none', 'typ' => 'JWT']));
        $header = rtrim(strtr($header, '+/', '-_'), '=');
        $payload = base64_encode(json_encode(['sub' => '1']));
        $payload = rtrim(strtr($payload, '+/', '-_'), '=');

        $this->expectException(AuthClientError::class);

        try {
            $validator->validateToken("{$header}.{$payload}.");
        } catch (AuthClientError $e) {
            $this->assertSame(AuthClientError::ALGORITHM_NOT_ALLOWED, $e->getErrorType());
            throw $e;
        }
    }
}