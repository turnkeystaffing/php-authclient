<?php

declare(strict_types=1);

namespace Turnkey\AuthClient\Tests\Discovery;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Turnkey\AuthClient\Discovery\ManifestValidationException;
use Turnkey\AuthClient\Discovery\ManifestValidator;
use Turnkey\AuthClient\Discovery\ScopeDefinition;
use Turnkey\AuthClient\Discovery\ScopeManifest;
use Turnkey\AuthClient\Discovery\TemplateDefinition;

class ManifestValidatorTest extends TestCase
{
    private static function scope(string $name, string $description = 'test'): ScopeDefinition
    {
        return new ScopeDefinition($name, $description);
    }

    /**
     * @return string[]
     */
    private static function errorsOf(ScopeManifest $manifest): array
    {
        try {
            ManifestValidator::validate($manifest);
        } catch (ManifestValidationException $e) {
            return $e->getErrors();
        }

        return [];
    }

    private function assertInvalid(ScopeManifest $manifest, string $contains): void
    {
        try {
            ManifestValidator::validate($manifest);
            $this->fail('expected ManifestValidationException');
        } catch (ManifestValidationException $e) {
            $this->assertStringContainsString($contains, $e->getMessage());
        }
    }

    #[DataProvider('validManifestProvider')]
    public function testValidManifests(ScopeManifest $manifest): void
    {
        ManifestValidator::validate($manifest);
        $this->addToAssertionCount(1);
    }

    public static function validManifestProvider(): iterable
    {
        yield 'minimal' => [new ScopeManifest('bgc', [self::scope('bgc:contractors:read')])];
        yield 'full' => [new ScopeManifest('bgc', [
            self::scope('bgc:contractors:read'),
            self::scope('bgc:contractors:write'),
        ], [
            new TemplateDefinition('viewer', ['bgc:contractors:read'], 'Read only'),
            new TemplateDefinition('editor', ['bgc:contractors:read', 'bgc:contractors:write']),
        ])];
        yield 'replaces external' => [new ScopeManifest('bgc', [self::scope('bgc:contractors:read')], [
            new TemplateDefinition('viewer', ['bgc:contractors:read'], replaces: 'legacy_viewer'),
        ])];
        yield 'wildcard final segment' => [new ScopeManifest('bgc', [self::scope('bgc:contractors:*')])];
        yield '2-segment wildcard' => [new ScopeManifest('bgc', [self::scope('bgc:*')])];
        yield '2-segment' => [new ScopeManifest('bgc', [self::scope('bgc:read')])];
        yield 'numbers and underscores' => [new ScopeManifest('svc_1', [self::scope('svc_1:res_2:act_3')])];
        yield 'multiple templates same replaces' => [new ScopeManifest('bgc', [self::scope('bgc:contractors:read')], [
            new TemplateDefinition('a', ['bgc:contractors:read'], replaces: 'old'),
            new TemplateDefinition('b', ['bgc:contractors:read'], replaces: 'old'),
        ])];
    }

    #[DataProvider('serviceCodeProvider')]
    public function testServiceCode(string $code, string $error): void
    {
        $this->assertInvalid(new ScopeManifest($code, [self::scope('bgc:read')]), $error);
    }

    public static function serviceCodeProvider(): iterable
    {
        yield 'empty' => ['', 'service_code is required'];
        yield 'uppercase' => ['BGC', 'must contain only lowercase'];
        yield 'hyphen' => ['bgc-app', 'must contain only lowercase'];
        yield 'colons' => ['bgc:app', 'must contain only lowercase'];
        yield 'spaces' => ['bgc app', 'must contain only lowercase'];
        yield 'special' => ['bgc@app', 'must contain only lowercase'];
    }

    #[DataProvider('scopeNameProvider')]
    public function testScopeNames(string $name, string $error): void
    {
        $this->assertInvalid(new ScopeManifest('bgc', [self::scope($name)]), $error);
    }

    public static function scopeNameProvider(): iterable
    {
        yield 'wrong prefix' => ['other:contractors:read', 'must start with service code'];
        yield '4+ segments' => ['bgc:a:b:c', 'must match pattern'];
        yield 'mid-segment wildcard' => ['bgc:*:read', 'wildcard in non-final segment'];
        yield 'embedded wildcard' => ['bgc:app*rove', 'embedded wildcard'];
        yield 'embedded wildcard final segment' => ['bgc:contractors:re*d', 'embedded wildcard'];
        yield 'too long' => ['bgc:' . str_repeat('a', 252), 'exceeds maximum length'];
        yield 'uppercase' => ['BGC:Contractors:Read', 'must be lowercase'];
        yield 'empty' => ['', 'scope name must not be empty'];
        yield 'single segment' => ['bgc', 'must match pattern'];
        yield 'trailing colon' => ['bgc:', 'must match pattern'];
        yield 'leading colon' => [':bgc:read', 'must match pattern'];
    }

    public function testScopeNameLengthBoundary(): void
    {
        $name = 'bgc:' . str_repeat('a', 251); // exactly 255
        $this->assertSame(255, strlen($name));
        ManifestValidator::validate(new ScopeManifest('bgc', [self::scope($name)]));
        $this->addToAssertionCount(1);
    }

    public function testDuplicateScopeNames(): void
    {
        $this->assertInvalid(
            new ScopeManifest('bgc', [self::scope('bgc:read'), self::scope('bgc:read')]),
            'duplicate scope name "bgc:read"',
        );
    }

    #[DataProvider('templateProvider')]
    public function testTemplates(TemplateDefinition $template, string $error, ?TemplateDefinition $second = null): void
    {
        $templates = $second === null ? [$template] : [$template, $second];
        $this->assertInvalid(new ScopeManifest('bgc', [self::scope('bgc:contractors:read')], $templates), $error);
    }

    public static function templateProvider(): iterable
    {
        yield 'empty name' => [new TemplateDefinition('', ['bgc:contractors:read']), 'name must not be empty'];
        yield 'empty scopes' => [new TemplateDefinition('viewer', []), 'must have at least one scope'];
        yield 'undefined scope' => [new TemplateDefinition('viewer', ['bgc:other:read']), 'references undefined scope'];
        yield 'duplicate refs' => [
            new TemplateDefinition('viewer', ['bgc:contractors:read', 'bgc:contractors:read']),
            'duplicate scope reference',
        ];
        yield 'duplicate names' => [
            new TemplateDefinition('viewer', ['bgc:contractors:read']),
            'duplicate template name',
            new TemplateDefinition('viewer', ['bgc:contractors:read']),
        ];
        yield 'replaces sibling' => [
            new TemplateDefinition('viewer', ['bgc:contractors:read']),
            'exists in the same manifest',
            new TemplateDefinition('editor', ['bgc:contractors:read'], replaces: 'viewer'),
        ];
        yield 'self replaces' => [
            new TemplateDefinition('viewer', ['bgc:contractors:read'], replaces: 'viewer'),
            'exists in the same manifest',
        ];
        yield 'name too long' => [
            new TemplateDefinition(str_repeat('a', 256), ['bgc:contractors:read']),
            'exceeds maximum length',
        ];
    }

    public function testCollectsAllErrorsInOrder(): void
    {
        $errors = self::errorsOf(new ScopeManifest('', []));
        $this->assertGreaterThanOrEqual(2, count($errors));
        $this->assertStringContainsString('service_code', $errors[0]);
        $this->assertStringContainsString('at least one scope', $errors[1]);
    }

    public function testInvalidServiceCodeSkipsScopeValidation(): void
    {
        $errors = self::errorsOf(new ScopeManifest('BAD', [self::scope('whatever')]));
        $this->assertCount(1, $errors);
    }

    public function testMixedValidAndInvalidScopes(): void
    {
        $errors = self::errorsOf(new ScopeManifest('bgc', [
            self::scope('bgc:contractors:read'),
            self::scope('BGC:CONTRACTORS:WRITE'),
            self::scope('other:contractors:read'),
        ], [new TemplateDefinition('viewer', ['bgc:contractors:read'])]));

        $this->assertCount(2, $errors);
        $joined = implode('; ', $errors);
        $this->assertStringContainsString('must be lowercase', $joined);
        $this->assertStringContainsString('must start with service code', $joined);
        $this->assertStringNotContainsString('undefined scope', $joined);
    }

    public function testTooManyScopesPreservesPriorErrors(): void
    {
        $scopes = [];
        for ($i = 0; $i <= ManifestValidator::MAX_SCOPES; $i++) {
            $scopes[] = self::scope("bgc:res:action{$i}");
        }
        $errors = implode('; ', self::errorsOf(new ScopeManifest('INVALID', $scopes)));
        $this->assertStringContainsString('must contain only lowercase', $errors);
        $this->assertStringContainsString('too many scopes', $errors);
    }

    public function testTooManyTemplatesPreservesPriorErrors(): void
    {
        $templates = [];
        for ($i = 0; $i <= ManifestValidator::MAX_TEMPLATES; $i++) {
            $templates[] = new TemplateDefinition("tmpl_{$i}", ['bgc:contractors:read']);
        }
        $errors = implode('; ', self::errorsOf(new ScopeManifest('', [self::scope('bgc:contractors:read')], $templates)));
        $this->assertStringContainsString('service_code is required', $errors);
        $this->assertStringContainsString('too many templates', $errors);
    }

    public function testErrorAccumulationCapped(): void
    {
        $scopes = [];
        for ($i = 0; $i < ManifestValidator::MAX_VALIDATION_ERRORS + 20; $i++) {
            $scopes[] = self::scope("INVALID_{$i}:BAD");
        }
        $errors = self::errorsOf(new ScopeManifest('bgc', $scopes));
        $this->assertCount(ManifestValidator::MAX_VALIDATION_ERRORS + 1, $errors);
        $this->assertStringContainsString('20 more errors', $errors[count($errors) - 1]);
    }

    public function testErrorMessageFormat(): void
    {
        $e = new ManifestValidationException(['a', 'b']);
        $this->assertSame('manifest validation failed: a; b', $e->getMessage());
    }
}
