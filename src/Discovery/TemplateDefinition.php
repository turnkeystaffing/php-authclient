<?php

declare(strict_types=1);

namespace Turnkey\AuthClient\Discovery;

/**
 * Declares a scope template that groups related scopes for role-based assignment.
 * The optional $replaces field references an external template name in the auth service
 * that this template supersedes during sync.
 */
final class TemplateDefinition implements \JsonSerializable
{
    private const FIELDS = ['name', 'description', 'scopes', 'replaces'];

    /**
     * @param string[] $scopes
     */
    public function __construct(
        public readonly string $name,
        public readonly array $scopes = [],
        public readonly string $description = '',
        public readonly string $replaces = '',
    ) {
    }

    /**
     * Strictly build from decoded data: unknown fields and non-scalar values are rejected.
     *
     * @throws ManifestException
     */
    public static function fromArray(mixed $data, string $path): self
    {
        $data = ManifestFields::mapping($data, $path, self::FIELDS);

        $scopes = [];
        foreach (ManifestFields::sequence($data, 'scopes', $path) as $i => $scope) {
            $scopes[] = ManifestFields::scalar($scope, "{$path}.scopes[{$i}]");
        }

        return new self(
            name: ManifestFields::string($data, 'name', $path),
            scopes: $scopes,
            description: ManifestFields::string($data, 'description', $path),
            replaces: ManifestFields::string($data, 'replaces', $path),
        );
    }

    public function jsonSerialize(): array
    {
        $out = ['name' => $this->name];
        if ($this->description !== '') {
            $out['description'] = $this->description;
        }
        $out['scopes'] = $this->scopes;
        if ($this->replaces !== '') {
            $out['replaces'] = $this->replaces;
        }

        return $out;
    }
}
