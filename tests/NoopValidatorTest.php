<?php

declare(strict_types=1);

namespace Turnkey\AuthClient\Tests;

use PHPUnit\Framework\TestCase;
use Turnkey\AuthClient\Claims;
use Turnkey\AuthClient\NoopValidator;

class NoopValidatorTest extends TestCase
{
    public function testReturnsDeepCopy(): void
    {
        $original = new Claims(
            clientId: 'dev',
            scopes: ['admin'],
            email: 'dev@test.com',
        );

        $validator = new NoopValidator($original);

        $result = $validator->validateToken('any-token');

        $this->assertSame('dev', $result->clientId);
        $this->assertSame(['admin'], $result->scopes);
        $this->assertSame('dev@test.com', $result->email);
        $this->assertNotSame($original, $result);
    }

    public function testDifferentTokensSameResult(): void
    {
        $validator = new NoopValidator(new Claims(clientId: 'dev'));

        $r1 = $validator->validateToken('token-a');
        $r2 = $validator->validateToken('token-b');

        $this->assertSame($r1->clientId, $r2->clientId);
        $this->assertNotSame($r1, $r2);
    }
}