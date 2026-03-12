<?php

declare(strict_types=1);

namespace Turnkey\AuthClient\Tests;

use PHPUnit\Framework\TestCase;
use Turnkey\AuthClient\Claims;
use Turnkey\AuthClient\ScopeChecker;

class ScopeCheckerTest extends TestCase
{
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
}