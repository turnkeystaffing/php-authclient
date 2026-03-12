<?php

declare(strict_types=1);

namespace Turnkey\AuthClient\Tests;

use PHPUnit\Framework\TestCase;
use Turnkey\AuthClient\AuthClientError;

class AuthClientErrorTest extends TestCase
{
    public function testErrorTypeAndMessage(): void
    {
        $error = new AuthClientError(AuthClientError::TOKEN_EXPIRED, 'custom message');
        $this->assertSame(AuthClientError::TOKEN_EXPIRED, $error->getErrorType());
        $this->assertSame('custom message', $error->getMessage());
    }

    public function testDefaultMessage(): void
    {
        $error = new AuthClientError(AuthClientError::TOKEN_EXPIRED);
        $this->assertSame(AuthClientError::TOKEN_EXPIRED, $error->getMessage());
    }

    public function testFactoryMethods(): void
    {
        $cases = [
            ['tokenOversized', AuthClientError::TOKEN_OVERSIZED],
            ['tokenMalformed', AuthClientError::TOKEN_MALFORMED],
            ['tokenExpired', AuthClientError::TOKEN_EXPIRED],
            ['tokenNotYetValid', AuthClientError::TOKEN_NOT_YET_VALID],
            ['tokenUnverifiable', AuthClientError::TOKEN_UNVERIFIABLE],
            ['tokenInvalid', AuthClientError::TOKEN_INVALID],
            ['algorithmNotAllowed', AuthClientError::ALGORITHM_NOT_ALLOWED],
            ['missingClientId', AuthClientError::MISSING_CLIENT_ID],
            ['introspectionFailed', AuthClientError::INTROSPECTION_FAILED],
            ['introspectionRejected', AuthClientError::INTROSPECTION_REJECTED],
            ['introspectionParse', AuthClientError::INTROSPECTION_PARSE],
            ['tokenInactive', AuthClientError::TOKEN_INACTIVE],
            ['tokenProviderClosed', AuthClientError::TOKEN_PROVIDER_CLOSED],
        ];

        foreach ($cases as [$method, $expectedType]) {
            $error = AuthClientError::$method();
            $this->assertSame($expectedType, $error->getErrorType(), "Factory method {$method}");
            $this->assertInstanceOf(AuthClientError::class, $error);
        }
    }

    public function testPreviousException(): void
    {
        $prev = new \RuntimeException('original');
        $error = AuthClientError::tokenMalformed('wrapped', $prev);
        $this->assertSame($prev, $error->getPrevious());
    }
}