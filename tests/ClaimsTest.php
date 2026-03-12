<?php

declare(strict_types=1);

namespace Turnkey\AuthClient\Tests;

use PHPUnit\Framework\TestCase;
use Turnkey\AuthClient\AuthClientError;
use Turnkey\AuthClient\Claims;

class ClaimsTest extends TestCase
{
    public function testConstructorDefaults(): void
    {
        $claims = new Claims(clientId: 'test-client');

        $this->assertSame('test-client', $claims->clientId);
        $this->assertSame([], $claims->scopes);
        $this->assertNull($claims->userId);
        $this->assertNull($claims->email);
        $this->assertNull($claims->username);
        $this->assertNull($claims->expiresAt);
        $this->assertNull($claims->subject);
        $this->assertSame([], $claims->audience);
        $this->assertNull($claims->issuedAt);
        $this->assertNull($claims->notBefore);
        $this->assertNull($claims->grantType);
        $this->assertNull($claims->authTime);
    }

    public function testConstructorAllFields(): void
    {
        $now = new \DateTimeImmutable();
        $claims = new Claims(
            clientId: 'c1',
            scopes: ['read', 'write'],
            userId: 'u1',
            email: 'test@example.com',
            username: 'testuser',
            expiresAt: $now,
            subject: 'sub1',
            audience: ['aud1'],
            issuedAt: $now,
            notBefore: $now,
            grantType: 'authorization_code',
            authTime: 1700000000,
        );

        $this->assertSame('c1', $claims->clientId);
        $this->assertSame(['read', 'write'], $claims->scopes);
        $this->assertSame('u1', $claims->userId);
        $this->assertSame('test@example.com', $claims->email);
        $this->assertSame('testuser', $claims->username);
        $this->assertSame($now, $claims->expiresAt);
        $this->assertSame('sub1', $claims->subject);
        $this->assertSame(['aud1'], $claims->audience);
        $this->assertSame('authorization_code', $claims->grantType);
        $this->assertSame(1700000000, $claims->authTime);
    }

    public function testDeepCopyIsIndependent(): void
    {
        $claims = new Claims(
            clientId: 'c1',
            scopes: ['read'],
            grantType: 'client_credentials',
            authTime: 1700000000,
        );

        $copy = $claims->deepCopy();

        $this->assertSame($claims->clientId, $copy->clientId);
        $this->assertSame($claims->scopes, $copy->scopes);
        $this->assertSame($claims->grantType, $copy->grantType);
        $this->assertSame($claims->authTime, $copy->authTime);
        $this->assertNotSame($claims, $copy);
    }

    public function testFromJwtPayloadWithClientId(): void
    {
        $payload = (object) [
            'client_id' => 'my-client',
            'scope' => 'read write',
            'sub' => 'user123',
            'aud' => 'api',
            'exp' => 1700000000,
            'iat' => 1699999000,
            'gty' => 'client_credentials',
            'auth_time' => 1699998000,
        ];

        $claims = Claims::fromJwtPayload($payload);

        $this->assertSame('my-client', $claims->clientId);
        $this->assertSame(['read', 'write'], $claims->scopes);
        $this->assertSame('user123', $claims->subject);
        $this->assertSame(['api'], $claims->audience);
        $this->assertSame('client_credentials', $claims->grantType);
        $this->assertSame(1699998000, $claims->authTime);
    }

    public function testFromJwtPayloadWithCid(): void
    {
        $payload = (object) ['cid' => 'alt-client'];
        $claims = Claims::fromJwtPayload($payload);
        $this->assertSame('alt-client', $claims->clientId);
    }

    public function testFromJwtPayloadWithScpArray(): void
    {
        $payload = (object) [
            'client_id' => 'c1',
            'scp' => ['admin', 'read'],
        ];

        $claims = Claims::fromJwtPayload($payload);
        $this->assertSame(['admin', 'read'], $claims->scopes);
    }

    public function testFromJwtPayloadMissingClientIdThrows(): void
    {
        $this->expectException(AuthClientError::class);

        Claims::fromJwtPayload((object) ['sub' => 'user1']);
    }

    public function testFromJwtPayloadFiltersEmptyScopes(): void
    {
        $payload = (object) [
            'client_id' => 'c1',
            'scope' => 'read  write',
        ];

        $claims = Claims::fromJwtPayload($payload);
        $this->assertSame(['read', 'write'], $claims->scopes);
    }

    public function testFromJwtPayloadOptionalFields(): void
    {
        $payload = (object) [
            'client_id' => 'c1',
            'user_id' => 'u1',
            'email' => 'a@b.com',
            'username' => 'bob',
        ];

        $claims = Claims::fromJwtPayload($payload);
        $this->assertSame('u1', $claims->userId);
        $this->assertSame('a@b.com', $claims->email);
        $this->assertSame('bob', $claims->username);
    }

    public function testAuthenticatedWithinRecentAuth(): void
    {
        $claims = new Claims(
            clientId: 'c1',
            authTime: time() - 60, // 1 minute ago
        );

        $this->assertTrue($claims->authenticatedWithin(300));
    }

    public function testAuthenticatedWithinExpiredAuth(): void
    {
        $claims = new Claims(
            clientId: 'c1',
            authTime: time() - 3600, // 1 hour ago
        );

        $this->assertFalse($claims->authenticatedWithin(300));
    }

    public function testAuthenticatedWithinNullAuthTime(): void
    {
        $claims = new Claims(clientId: 'c1');
        $this->assertFalse($claims->authenticatedWithin());
    }

    public function testAuthenticatedWithinZeroAuthTime(): void
    {
        $claims = new Claims(clientId: 'c1', authTime: 0);
        $this->assertFalse($claims->authenticatedWithin());
    }

    public function testAuthenticatedWithinDefaultMaxAge(): void
    {
        // Within 15 minutes
        $claims = new Claims(clientId: 'c1', authTime: time() - 800);
        $this->assertTrue($claims->authenticatedWithin());

        // Beyond 15 minutes
        $claims = new Claims(clientId: 'c1', authTime: time() - 1000);
        $this->assertFalse($claims->authenticatedWithin());
    }
}