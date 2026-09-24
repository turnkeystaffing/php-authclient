<?php

declare(strict_types=1);

namespace Turnkey\AuthClient\Tests\Discovery;

use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Request;
use Turnkey\AuthClient\Discovery\DiscoveryHandler;
use Turnkey\AuthClient\Discovery\ManifestException;
use Turnkey\AuthClient\Discovery\ManifestValidationException;
use Turnkey\AuthClient\Discovery\ScopeDefinition;
use Turnkey\AuthClient\Discovery\ScopeManifest;

class DiscoveryHandlerTest extends TestCase
{
    private const YAML_V1 = "service_code: bgc\nscopes:\n  - name: bgc:contractors:read\n    description: Read\n";
    private const YAML_V2 = "service_code: bgc\nscopes:\n  - name: bgc:contractors:write\n    description: Write\n";

    private string $path;

    protected function setUp(): void
    {
        $this->path = sys_get_temp_dir() . '/discovery_' . bin2hex(random_bytes(6)) . '.yaml';
        file_put_contents($this->path, self::YAML_V1);
    }

    protected function tearDown(): void
    {
        @unlink($this->path);
    }

    public function testGetServesManifestJson(): void
    {
        $handler = DiscoveryHandler::fromManifest(new ScopeManifest('bgc', [new ScopeDefinition('bgc:read', 'Read')]));
        $response = $handler(Request::create('/.well-known/scopes', 'GET'));

        $this->assertSame(200, $response->getStatusCode());
        $this->assertSame('{"service_code":"bgc","scopes":[{"name":"bgc:read","description":"Read"}]}', $response->getContent());
        $this->assertSame('application/json', $response->headers->get('Content-Type'));
        $this->assertStringContainsString('no-store', (string) $response->headers->get('Cache-Control'));
        $this->assertSame('nosniff', $response->headers->get('X-Content-Type-Options'));
    }

    public function testNonGetReturns405(): void
    {
        $handler = DiscoveryHandler::fromFile($this->path);
        foreach (['POST', 'PUT', 'DELETE', 'PATCH', 'HEAD'] as $method) {
            $response = $handler(Request::create('/', $method));
            $this->assertSame(405, $response->getStatusCode(), $method);
            $this->assertSame('GET', $response->headers->get('Allow'));
            $this->assertSame('nosniff', $response->headers->get('X-Content-Type-Options'));
            $this->assertSame(
                '{"error":"method_not_allowed","error_description":"Only GET is supported"}',
                $response->getContent(),
            );
        }
    }

    public function testFromManifestValidates(): void
    {
        $this->expectException(ManifestValidationException::class);
        DiscoveryHandler::fromManifest(new ScopeManifest('bgc', [new ScopeDefinition('other:read')]));
    }

    public function testFromFileErrors(): void
    {
        try {
            DiscoveryHandler::fromFile('');
            $this->fail('expected exception');
        } catch (\InvalidArgumentException $e) {
            $this->assertStringContainsString('path cannot be empty', $e->getMessage());
        }

        $this->expectException(ManifestException::class);
        $this->expectExceptionMessage('discovery handler:');
        DiscoveryHandler::fromFile($this->path . '.missing.yaml');
    }

    public function testReloadReplacesManifest(): void
    {
        $handler = DiscoveryHandler::fromFile($this->path);
        $this->assertStringContainsString('bgc:contractors:read', $handler->getJson());

        file_put_contents($this->path, self::YAML_V2);
        $handler->reload();

        $content = (string) $handler(Request::create('/', 'GET'))->getContent();
        $this->assertStringContainsString('bgc:contractors:write', $content);
        $this->assertStringNotContainsString('bgc:contractors:read', $content);
    }

    public function testReloadFailurePreservesPreviousManifest(): void
    {
        $handler = DiscoveryHandler::fromFile($this->path);
        $before = $handler->getJson();

        file_put_contents($this->path, "service_code: BAD\nscopes: []\n");
        try {
            $handler->reload();
            $this->fail('expected reload to fail');
        } catch (ManifestException) {
        }
        $this->assertSame($before, $handler->getJson());

        unlink($this->path);
        try {
            $handler->reload();
            $this->fail('expected reload to fail');
        } catch (ManifestException) {
        }
        $this->assertSame($before, (string) $handler(Request::create('/', 'GET'))->getContent());
    }

    public function testReloadWithoutFileThrows(): void
    {
        $handler = DiscoveryHandler::fromManifest(new ScopeManifest('bgc', [new ScopeDefinition('bgc:read')]));
        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('reload requires file-based handler');
        $handler->reload();
    }
}
