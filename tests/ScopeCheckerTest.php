<?php

declare(strict_types=1);

namespace Turnkey\AuthClient\Tests;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Turnkey\AuthClient\Claims;
use Turnkey\AuthClient\ScopeChecker;

class ScopeCheckerTest extends TestCase
{
    // --- hasScope: exact matching ---

    public function testHasScopeMatch(): void
    {
        $claims = new Claims(clientId: 'c1', scopes: ['read', 'write', 'admin']);
        $this->assertTrue(ScopeChecker::hasScope($claims, 'admin'));
    }

    public function testHasScopeNoMatch(): void
    {
        $claims = new Claims(clientId: 'c1', scopes: ['read']);
        $this->assertFalse(ScopeChecker::hasScope($claims, 'admin'));
    }

    public function testHasScopeNullClaims(): void
    {
        $this->assertFalse(ScopeChecker::hasScope(null, 'read'));
    }

    public function testHasScopeEmptyScope(): void
    {
        $claims = new Claims(clientId: 'c1', scopes: ['read']);
        $this->assertFalse(ScopeChecker::hasScope($claims, ''));
    }

    public function testHasScopeCaseSensitive(): void
    {
        $claims = new Claims(clientId: 'c1', scopes: ['Read']);
        $this->assertFalse(ScopeChecker::hasScope($claims, 'read'));
    }

    // --- hasScope: wildcard matching ---

    public function testHasScopeWildcardTwoSegment(): void
    {
        $claims = new Claims(clientId: 'c1', scopes: ['expenses:*']);
        $this->assertTrue(ScopeChecker::hasScope($claims, 'expenses:approve'));
        $this->assertTrue(ScopeChecker::hasScope($claims, 'expenses:submit'));
        $this->assertFalse(ScopeChecker::hasScope($claims, 'admin:read'));
    }

    public function testHasScopeWildcardThreeSegment(): void
    {
        $claims = new Claims(clientId: 'c1', scopes: ['bgc:contractors:*']);
        $this->assertTrue(ScopeChecker::hasScope($claims, 'bgc:contractors:read'));
        $this->assertTrue(ScopeChecker::hasScope($claims, 'bgc:contractors:write'));
        $this->assertFalse(ScopeChecker::hasScope($claims, 'bgc:expenses:read'));
    }

    public function testHasScopeServiceLevelWildcard(): void
    {
        $claims = new Claims(clientId: 'c1', scopes: ['bgc:*']);
        $this->assertTrue(ScopeChecker::hasScope($claims, 'bgc:contractors:read'));
        $this->assertTrue(ScopeChecker::hasScope($claims, 'bgc:expenses:approve'));
        $this->assertFalse(ScopeChecker::hasScope($claims, 'admin:read'));
    }

    public function testHasScopeUniversalWildcard(): void
    {
        $claims = new Claims(clientId: 'c1', scopes: ['*:*']);
        $this->assertTrue(ScopeChecker::hasScope($claims, 'admin:read'));
        $this->assertTrue(ScopeChecker::hasScope($claims, 'bgc:contractors:write'));
    }

    public function testHasScopeStarWildcard(): void
    {
        $claims = new Claims(clientId: 'c1', scopes: ['*']);
        $this->assertTrue(ScopeChecker::hasScope($claims, 'anything'));
        $this->assertTrue(ScopeChecker::hasScope($claims, 'admin:read'));
    }

    public function testHasScopeNoBidirectionalWildcard(): void
    {
        // User with specific scope should NOT satisfy a wildcard requirement
        $claims = new Claims(clientId: 'c1', scopes: ['admin:read']);
        $this->assertFalse(ScopeChecker::hasScope($claims, 'admin:*'));
    }

    // --- hasAnyScope ---

    public function testHasAnyScopeMatch(): void
    {
        $claims = new Claims(clientId: 'c1', scopes: ['write']);
        $this->assertTrue(ScopeChecker::hasAnyScope($claims, ['read', 'write']));
    }

    public function testHasAnyScopeNoMatch(): void
    {
        $claims = new Claims(clientId: 'c1', scopes: ['delete']);
        $this->assertFalse(ScopeChecker::hasAnyScope($claims, ['read', 'write']));
    }

    public function testHasAnyScopeNullClaims(): void
    {
        $this->assertFalse(ScopeChecker::hasAnyScope(null, ['read']));
    }

    public function testHasAnyScopeSkipsEmptyStrings(): void
    {
        $claims = new Claims(clientId: 'c1', scopes: ['read']);
        $this->assertTrue(ScopeChecker::hasAnyScope($claims, ['', 'read']));
    }

    public function testHasAnyScopeAllEmpty(): void
    {
        $claims = new Claims(clientId: 'c1', scopes: ['read']);
        $this->assertFalse(ScopeChecker::hasAnyScope($claims, ['', '']));
    }

    public function testHasAnyScopeWithWildcard(): void
    {
        $claims = new Claims(clientId: 'c1', scopes: ['admin:*']);
        $this->assertTrue(ScopeChecker::hasAnyScope($claims, ['admin:read', 'other:write']));
    }

    // --- hasAllScopes ---

    public function testHasAllScopesGranted(): void
    {
        $claims = new Claims(clientId: 'c1', scopes: ['read', 'write', 'admin']);
        $this->assertTrue(ScopeChecker::hasAllScopes($claims, ['read', 'write']));
    }

    public function testHasAllScopesMissing(): void
    {
        $claims = new Claims(clientId: 'c1', scopes: ['read']);
        $this->assertFalse(ScopeChecker::hasAllScopes($claims, ['read', 'write']));
    }

    public function testHasAllScopesNullClaims(): void
    {
        $this->assertFalse(ScopeChecker::hasAllScopes(null, ['read']));
    }

    public function testHasAllScopesWithWildcard(): void
    {
        $claims = new Claims(clientId: 'c1', scopes: ['admin:*']);
        $this->assertTrue(ScopeChecker::hasAllScopes($claims, ['admin:read', 'admin:write']));
        $this->assertFalse(ScopeChecker::hasAllScopes($claims, ['admin:read', 'other:write']));
    }

    // --- matchesPattern ---

    #[DataProvider('patternMatchProvider')]
    public function testMatchesPattern(string $pattern, string $scope, bool $expected): void
    {
        $this->assertSame($expected, ScopeChecker::matchesPattern($pattern, $scope));
    }

    public static function patternMatchProvider(): iterable
    {
        // Exact match
        yield 'exact' => ['expenses:approve', 'expenses:approve', true];
        yield 'exact mismatch' => ['expenses:approve', 'expenses:submit', false];

        // Universal wildcards
        yield '*:* matches 2-seg' => ['*:*', 'admin:read', true];
        yield '*:* matches 3-seg' => ['*:*', 'bgc:contractors:read', true];
        yield '* matches anything' => ['*', 'admin:read', true];

        // Trailing wildcard — 2-segment
        yield '2-seg wildcard match' => ['expenses:*', 'expenses:approve', true];
        yield '2-seg wildcard spans' => ['bgc:*', 'bgc:contractors:read', true];
        yield '2-seg wildcard wrong prefix' => ['expenses:*', 'admin:read', false];

        // Trailing wildcard — 3-segment
        yield '3-seg wildcard match' => ['bgc:contractors:*', 'bgc:contractors:read', true];
        yield '3-seg wildcard wrong resource' => ['bgc:contractors:*', 'bgc:expenses:read', false];

        // No wildcard, no match
        yield 'no wildcard diff' => ['admin:read', 'admin:write', false];

        // Empty segments rejected
        yield 'pattern trailing colon' => ['admin:', 'admin:read', false];
        yield 'scope trailing colon' => ['admin:*', 'admin:', false];

        // Scope must have at least one segment at wildcard position
        yield 'wildcard needs segment' => ['admin:*', 'admin', false];
    }
}