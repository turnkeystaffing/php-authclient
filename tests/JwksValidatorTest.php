<?php

declare(strict_types=1);

namespace Turnkey\AuthClient\Tests;

use PHPUnit\Framework\TestCase;
use Turnkey\AuthClient\AuthClientError;
use Turnkey\AuthClient\JwksProvider;
use Turnkey\AuthClient\JwksValidator;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;
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

    // --- signed token validation ---

    private static ?\OpenSSLAsymmetricKey $privateKey = null;

    private static function privateKey(): \OpenSSLAsymmetricKey
    {
        return self::$privateKey ??= openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
    }

    /**
     * @param string|string[] $audience
     */
    private function signedValidator(string|array $audience = 'api'): JwksValidator
    {
        $public = openssl_pkey_get_details(self::privateKey())['key'];
        $provider = $this->createStub(JwksProvider::class);
        $provider->method('getKeys')->willReturn(['kid1' => new Key($public, 'RS256')]);

        return new JwksValidator($provider, 'https://issuer.com', $audience, new NullLogger());
    }

    private static function sign(array $claims): string
    {
        return JWT::encode($claims + ['iss' => 'https://issuer.com', 'client_id' => 'c1'], self::privateKey(), 'RS256', 'kid1');
    }

    public function testValidSignedToken(): void
    {
        $claims = $this->signedValidator()->validateToken(self::sign(['aud' => 'api', 'exp' => time() + 60, 'scope' => 'svc:data:read']));
        $this->assertSame('c1', $claims->clientId);
        $this->assertSame(['svc:data:read'], $claims->scopes);
    }

    public function testMissingExpRejected(): void
    {
        try {
            $this->signedValidator()->validateToken(self::sign(['aud' => 'api']));
            $this->fail('expected AuthClientError');
        } catch (AuthClientError $e) {
            $this->assertSame(AuthClientError::TOKEN_INVALID, $e->getErrorType());
            $this->assertStringContainsString('exp', $e->getMessage());
        }
    }

    public function testMultipleAudiencesAnyMatch(): void
    {
        $validator = $this->signedValidator(['api', 'admin-api']);
        $claims = $validator->validateToken(self::sign(['aud' => ['other', 'admin-api'], 'exp' => time() + 60]));
        $this->assertSame('c1', $claims->clientId);

        $this->expectException(AuthClientError::class);
        $validator->validateToken(self::sign(['aud' => 'unrelated', 'exp' => time() + 60]));
    }

    public function testEmptyAudienceListRejected(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        new JwksValidator($this->createStub(JwksProvider::class), 'https://issuer.com', ['', ''], new NullLogger());
    }

    public function testEmptyIssuerRejected(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('issuer is required');
        new JwksValidator($this->createStub(JwksProvider::class), '', 'api', new NullLogger());
    }
}
