<?php

declare(strict_types=1);

namespace Turnkey\AuthClient\Discovery;

/**
 * Declares a single scope within a service manifest.
 */
final class ScopeDefinition implements \JsonSerializable
{
    private const FIELDS = ['name', 'description', 'category'];

    public function __construct(
        public readonly string $name,
        public readonly string $description = '',
        public readonly string $category = '',
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

        return new self(
            name: ManifestFields::string($data, 'name', $path),
            description: ManifestFields::string($data, 'description', $path),
            category: ManifestFields::string($data, 'category', $path),
        );
    }

    /**
     * @return array<string, mixed>
     */
    public function jsonSerialize(): array
    {
        $out = ['name' => $this->name, 'description' => $this->description];
        if ($this->category !== '') {
            $out['category'] = $this->category;
        }

        return $out;
    }
}
