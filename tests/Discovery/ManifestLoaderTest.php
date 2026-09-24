<?php

declare(strict_types=1);

namespace Turnkey\AuthClient\Tests\Discovery;

use PHPUnit\Framework\TestCase;
use Turnkey\AuthClient\Discovery\ManifestException;
use Turnkey\AuthClient\Discovery\ManifestLoader;
use Turnkey\AuthClient\Discovery\ManifestValidationException;
use Turnkey\AuthClient\Discovery\ScopeDefinition;
use Turnkey\AuthClient\Discovery\ScopeManifest;
use Turnkey\AuthClient\Discovery\TemplateDefinition;

class ManifestLoaderTest extends TestCase
{
    private const YAML = "service_code: bgc\nscopes:\n  - name: bgc:contractors:read\n    description: Read contractors\n";

    private string $dir;

    protected function setUp(): void
    {
        $this->dir = sys_get_temp_dir() . '/manifest_' . bin2hex(random_bytes(6));
        mkdir($this->dir);
    }

    protected function tearDown(): void
    {
        foreach (glob($this->dir . '/*') ?: [] as $f) {
            is_dir($f) ? rmdir($f) : unlink($f);
        }
        rmdir($this->dir);
    }

    private function write(string $name, string $content): string
    {
        $path = $this->dir . '/' . $name;
        file_put_contents($path, $content);

        return $path;
    }

    private function assertLoadFails(callable $fn, ?string $contains = null): void
    {
        try {
            $fn();
            $this->fail('expected ManifestException');
        } catch (ManifestException $e) {
            if ($contains !== null) {
                $this->assertStringContainsString($contains, $e->getMessage());
            }
        }
    }

    public function testFromYamlFile(): void
    {
        $m = ManifestLoader::fromFile($this->write('manifest.yaml', self::YAML));
        $this->assertSame('bgc', $m->serviceCode);
        $this->assertCount(1, $m->scopes);
        $this->assertSame('bgc:contractors:read', $m->scopes[0]->name);
        $this->assertSame('Read contractors', $m->scopes[0]->description);
    }

    public function testFromYmlAndUppercaseExtension(): void
    {
        $this->assertSame('bgc', ManifestLoader::fromFile($this->write('m.yml', self::YAML))->serviceCode);
        $this->assertSame('bgc', ManifestLoader::fromFile($this->write('m.YAML', self::YAML))->serviceCode);
    }

    public function testFromJsonFile(): void
    {
        $json = '{"service_code":"bgc","scopes":[{"name":"bgc:read","description":"Read","category":"data"}],'
            . '"templates":[{"name":"viewer","scopes":["bgc:read"],"replaces":"old"}]}';
        $m = ManifestLoader::fromFile($this->write('m.json', $json));
        $this->assertSame('data', $m->scopes[0]->category);
        $this->assertSame('old', $m->templates[0]->replaces);
    }

    public function testFileErrors(): void
    {
        $this->assertLoadFails(fn() => ManifestLoader::fromFile($this->write('manifest', 'service_code: bgc')), 'unsupported file extension');
        $this->assertLoadFails(fn() => ManifestLoader::fromFile($this->dir . '/missing.yaml'), 'opening manifest file');
        mkdir($this->dir . '/dir.yaml');
        $this->assertLoadFails(fn() => ManifestLoader::fromFile($this->dir . '/dir.yaml'));
        $this->assertLoadFails(fn() => ManifestLoader::fromFile($this->write('empty.yaml', '')));
        $this->assertLoadFails(fn() => ManifestLoader::fromFile($this->write('empty.json', '')));
        $this->assertLoadFails(fn() => ManifestLoader::fromFile($this->write('bad.json', '{not valid json}')), 'parsing JSON');
    }

    public function testValidationErrorPropagates(): void
    {
        $this->expectException(ManifestValidationException::class);
        ManifestLoader::fromString("service_code: bgc\nscopes:\n  - name: other:read\n", 'yaml');
    }

    public function testFormatErrors(): void
    {
        $this->assertLoadFails(fn() => ManifestLoader::fromString('{}', ''), 'format is required');
        $this->assertLoadFails(fn() => ManifestLoader::fromString('{}', 'toml'), 'unsupported format');
        $this->assertSame('bgc', ManifestLoader::fromString(self::YAML, 'YAML')->serviceCode);
    }

    public function testExceedsMaxSize(): void
    {
        $this->assertLoadFails(
            fn() => ManifestLoader::fromString(str_repeat('x', ManifestLoader::MAX_SIZE + 1), 'yaml'),
            'exceeds maximum size',
        );
    }

    public function testUnknownFieldsRejected(): void
    {
        $this->assertLoadFails(
            fn() => ManifestLoader::fromString("service_code: bgc\nservide_code: typo\nscopes:\n  - name: bgc:read\n    description: Read\n", 'yaml'),
            'parsing YAML',
        );
        $this->assertLoadFails(
            fn() => ManifestLoader::fromString('{"service_code":"bgc","servide_code":"typo","scopes":[{"name":"bgc:read","description":"Read"}]}', 'json'),
            'parsing JSON',
        );
        $this->assertLoadFails(
            fn() => ManifestLoader::fromString('{"service_code":"bgc","scopes":[{"name":"bgc:read","extra":1}]}', 'json'),
            'unknown field "extra"',
        );
    }

    public function testWrongTypesRejected(): void
    {
        $this->assertLoadFails(fn() => ManifestLoader::fromString('{"service_code":"bgc","scopes":"bgc:read"}', 'json'), 'must be a list');
        $this->assertLoadFails(fn() => ManifestLoader::fromString('{"service_code":["x"],"scopes":[]}', 'json'), 'must be a string');
        $this->assertLoadFails(fn() => ManifestLoader::fromString('["bgc"]', 'json'), 'must be a mapping');
    }

    public function testYamlAnchorAlias(): void
    {
        $yaml = <<<YAML
        service_code: bgc
        scopes:
          - &base_scope
            name: bgc:contractors:read
            description: Read contractors
          - <<: *base_scope
            name: bgc:contractors:write
            description: Write contractors
        YAML;
        $m = ManifestLoader::fromString($yaml, 'yaml');
        $this->assertCount(2, $m->scopes);
        $this->assertSame('bgc:contractors:write', $m->scopes[1]->name);
    }

    public function testJsonRoundTrip(): void
    {
        $m = new ScopeManifest('bgc', [
            new ScopeDefinition('bgc:contractors:read', 'Read <contractors> & more', 'data'),
            new ScopeDefinition('bgc:contractors:write', 'Write'),
        ], [new TemplateDefinition('viewer', ['bgc:contractors:read'], 'Viewer', 'legacy')]);

        $json = $m->toJson();
        $this->assertSame(
            '{"service_code":"bgc","scopes":[{"name":"bgc:contractors:read","description":"Read \u003Ccontractors\u003E \u0026 more","category":"data"},'
            . '{"name":"bgc:contractors:write","description":"Write"}],'
            . '"templates":[{"name":"viewer","description":"Viewer","scopes":["bgc:contractors:read"],"replaces":"legacy"}]}',
            $json,
        );
        $this->assertEquals($m, ManifestLoader::fromString($json, 'json'));
    }

    public function testJsonOmitsEmptyTemplates(): void
    {
        $json = (new ScopeManifest('bgc', [new ScopeDefinition('bgc:read')]))->toJson();
        $this->assertSame('{"service_code":"bgc","scopes":[{"name":"bgc:read","description":""}]}', $json);
    }
}
