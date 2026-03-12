<?php

declare(strict_types=1);

namespace Turnkey\AuthClient\Tests;

use PHPUnit\Framework\TestCase;
use Turnkey\AuthClient\AuthClientError;
use Turnkey\AuthClient\IntrospectionResponse;

class IntrospectionResponseTest extends TestCase
{
    public function testFromArrayActive(): void
    {
        $data = [
            'active' => true,
            'client_id' => 'c1',
            'username' => 'bob',
            'token_type' => 'Bearer',
            'exp' => 1700000000,
            'iat' => 1699999000,
            'nbf' => 1699999000,
            'sub' => 'user1',
            'aud' => 'api',
            'iss' => 'https://auth.example.com',
            'scope' => 'read write',
            'gty' => 'authorization_code',
            'auth_time' => 1699998000,
        ];

        $response = IntrospectionResponse::fromArray($data);

        $this->assertTrue($response->active);
        $this->assertSame('c1', $response->clientId);
        $this->assertSame('bob', $response->username);
        $this->assertSame('Bearer', $response->tokenType);
        $this->assertSame(1700000000, $response->exp);
        $this->assertSame(1699999000, $response->iat);
        $this->assertSame('authorization_code', $response->grantType);
        $this->assertSame(1699998000, $response->authTime);
    }

    public function testFromArrayInactive(): void
    {
        $response = IntrospectionResponse::fromArray(['active' => false]);
        $this->assertFalse($response->active);
    }

    public function testFromArrayMissingActiveDefaultsFalse(): void
    {
        $response = IntrospectionResponse::fromArray([]);
        $this->assertFalse($response->active);
    }

    public function testToClaimsActive(): void
    {
        $response = new IntrospectionResponse(
            active: true,
            clientId: 'c1',
            scope: 'read admin',
            sub: 'u1',
            exp: 1700000000,
            grantType: 'client_credentials',
            authTime: 1699998000,
        );

        $claims = $response->toClaims();

        $this->assertSame('c1', $claims->clientId);
        $this->assertSame(['read', 'admin'], $claims->scopes);
        $this->assertSame('u1', $claims->subject);
        $this->assertSame('client_credentials', $claims->grantType);
        $this->assertSame(1699998000, $claims->authTime);
    }

    public function testToClaimsInactiveThrows(): void
    {
        $response = new IntrospectionResponse(active: false, clientId: 'c1');

        $this->expectException(AuthClientError::class);
        $response->toClaims();
    }

    public function testToClaimsMissingClientIdThrows(): void
    {
        $response = new IntrospectionResponse(active: true);

        $this->expectException(AuthClientError::class);
        $response->toClaims();
    }

    public function testToClaimsNullScope(): void
    {
        $response = new IntrospectionResponse(active: true, clientId: 'c1');
        $claims = $response->toClaims();
        $this->assertSame([], $claims->scopes);
    }
}