<?php

declare(strict_types=1);

namespace Turnkey\AuthClient\Tests;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Turnkey\AuthClient\ScopeValidator;

class ScopeValidatorTest extends TestCase
{
    // --- validateName: valid names ---

    #[DataProvider('validNameProvider')]
    public function testValidateName(string $name): void
    {
        ScopeValidator::validateName($name);
        $this->addToAssertionCount(1);
    }

    public static function validNameProvider(): iterable
    {
        // OIDC standard scopes
        yield 'openid' => ['openid'];
        yield 'profile' => ['profile'];
        yield 'email' => ['email'];
        yield 'address' => ['address'];
        yield 'phone' => ['phone'];
        yield 'offline_access' => ['offline_access'];

        // 2-segment (resource:action)
        yield 'expenses:approve' => ['expenses:approve'];
        yield 'users:read' => ['users:read'];
        yield 'data_export:run' => ['data_export:run'];

        // 3-segment (service:resource:action)
        yield 'bgc:contractors:read' => ['bgc:contractors:read'];
        yield 'admin:users:write' => ['admin:users:write'];
        yield 'svc1:res2:act3' => ['svc1:res2:act3'];

        // Wildcards
        yield 'admin:*' => ['admin:*'];
        yield 'bgc:contractors:*' => ['bgc:contractors:*'];
        yield '*:*' => ['*:*'];
        yield '*' => ['*'];
    }

    // --- validateName: invalid names ---

    #[DataProvider('invalidNameProvider')]
    public function testValidateNameRejects(string $name, string $expectedMessagePart): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessageMatches('/' . preg_quote($expectedMessagePart, '/') . '/');
        ScopeValidator::validateName($name);
    }

    public static function invalidNameProvider(): iterable
    {
        yield 'empty' => ['', 'cannot be empty'];
        yield 'too long' => [str_repeat('a', 256), 'cannot exceed 255'];
        yield 'uppercase' => ['Admin:read', 'must be lowercase'];
        yield 'mixed case' => ['expenses:Approve', 'must be lowercase'];
        yield 'single segment' => ['admin', 'must match pattern'];
        yield '4 segments' => ['a:b:c:d', 'must match pattern'];
        yield 'spaces' => ['admin: read', 'must match pattern'];
        yield 'special chars' => ['admin:re@d', 'must match pattern'];
        yield 'embedded wildcard' => ['admin:re*d', 'must be the entire segment'];
        yield 'mid-segment wildcard' => ['admin:*:read', 'only allowed as the final segment'];
    }

    // --- validateScopePrefix ---

    public function testValidateScopePrefixMatch(): void
    {
        ScopeValidator::validateScopePrefix('bgc:contractors:read', 'bgc');
        $this->addToAssertionCount(1);
    }

    public function testValidateScopePrefixMismatch(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessageMatches("/must match service code 'bgc'/");
        ScopeValidator::validateScopePrefix('admin:users:read', 'bgc');
    }

    public function testValidateScopePrefixSkippedWhenNull(): void
    {
        ScopeValidator::validateScopePrefix('anything:here', null);
        $this->addToAssertionCount(1);
    }

    public function testValidateScopePrefixSkippedWhenEmpty(): void
    {
        ScopeValidator::validateScopePrefix('anything:here', '');
        $this->addToAssertionCount(1);
    }

    public function testValidateScopePrefixNoColon(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessageMatches('/has no prefix segment/');
        ScopeValidator::validateScopePrefix('openid', 'myapp');
    }

    // --- validateScopeNames ---

    public function testValidateScopeNamesValid(): void
    {
        ScopeValidator::validateScopeNames(['expenses:approve', 'admin:*', 'openid']);
        $this->addToAssertionCount(1);
    }

    public function testValidateScopeNamesEmpty(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessageMatches('/cannot be empty/');
        ScopeValidator::validateScopeNames([]);
    }

    public function testValidateScopeNamesInvalidEntry(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessageMatches('/index 1/');
        ScopeValidator::validateScopeNames(['expenses:approve', 'BAD']);
    }

    // --- helpers ---

    public function testIsOidcStandardScope(): void
    {
        $this->assertTrue(ScopeValidator::isOidcStandardScope('openid'));
        $this->assertTrue(ScopeValidator::isOidcStandardScope('offline_access'));
        $this->assertFalse(ScopeValidator::isOidcStandardScope('admin:read'));
        $this->assertFalse(ScopeValidator::isOidcStandardScope('custom'));
    }

    public function testContainsWildcard(): void
    {
        $this->assertTrue(ScopeValidator::containsWildcard('admin:*'));
        $this->assertTrue(ScopeValidator::containsWildcard('*:*'));
        $this->assertFalse(ScopeValidator::containsWildcard('admin:read'));
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('isValidScopeProvider')]
    public function testIsValidScope(string $name, bool $expected): void
    {
        $this->assertSame($expected, ScopeValidator::isValidScope($name));
    }

    public static function isValidScopeProvider(): iterable
    {
        yield 'oidc openid' => ['openid', true];
        yield 'oidc offline_access' => ['offline_access', true];
        yield '2-seg' => ['expenses:approve', true];
        yield '3-seg' => ['bgc:contractors:read', true];
        yield 'final wildcard 2-seg' => ['bgc:*', true];
        yield 'final wildcard 3-seg' => ['bgc:contractors:*', true];
        yield 'universal *:*' => ['*:*', true];
        yield 'universal *' => ['*', true];
        yield 'empty' => ['', false];
        yield 'too long' => ['a:' . str_repeat('b', 255), false];
        yield 'uppercase' => ['Admin:read', false];
        yield 'single segment' => ['admin', false];
        yield '4 segments' => ['a:b:c:d', false];
        yield 'triple colon' => ['bogus:::thing', false];
        yield 'trailing colon' => ['admin:', false];
        yield 'non-final wildcard' => ['bgc:*:read', false];
        yield 'embedded wildcard' => ['svc:app*rove', false];
        yield 'wildcard first segment' => ['*:read', false];
        yield 'special chars' => ['svc:data-read', false];
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('isValidScopeProvider')]
    public function testIsValidScopeAgreesWithValidateName(string $name, bool $expected): void
    {
        try {
            ScopeValidator::validateName($name);
            $valid = true;
        } catch (\InvalidArgumentException) {
            $valid = false;
        }
        $this->assertSame($expected, $valid);
    }
}
