<?php

declare(strict_types=1);

namespace Turnkey\AuthClient\Discovery;

/**
 * Declares a service's scopes and templates for discovery by the auth service.
 * Serialized as JSON for HTTP discovery (see DiscoveryHandler) or loaded from
 * YAML/JSON files (see ManifestLoader).
 */
final class ScopeManifest implements \JsonSerializable
{
    private const FIELDS = ['service_code', 'scopes', 'templates'];

    /**
     * @param ScopeDefinition[] $scopes
     * @param TemplateDefinition[] $templates
     */
    public function __construct(
        public readonly string $serviceCode,
        public readonly array $scopes = [],
        public readonly array $templates = [],
    ) {
    }

    /**
     * Strictly build from decoded data: unknown fields and non-scalar values are rejected.
     * Does NOT validate the manifest contents — use ManifestValidator::validate().
     *
     * @throws ManifestException
     */
    public static function fromArray(mixed $data): self
    {
        $data = ManifestFields::mapping($data, 'manifest', self::FIELDS);

        $scopes = [];
        foreach (ManifestFields::sequence($data, 'scopes', 'manifest') as $i => $scope) {
            $scopes[] = ScopeDefinition::fromArray($scope, "scopes[{$i}]");
        }

        $templates = [];
        foreach (ManifestFields::sequence($data, 'templates', 'manifest') as $i => $template) {
            $templates[] = TemplateDefinition::fromArray($template, "templates[{$i}]");
        }

        return new self(
            serviceCode: ManifestFields::string($data, 'service_code', 'manifest'),
            scopes: $scopes,
            templates: $templates,
        );
    }

    /**
     * @return array<string, mixed>
     */
    public function jsonSerialize(): array
    {
        $out = ['service_code' => $this->serviceCode, 'scopes' => $this->scopes];
        if ($this->templates !== []) {
            $out['templates'] = $this->templates;
        }

        return $out;
    }

    /**
     * Serialize to JSON using the same escaping rules as Go's encoding/json
     * (HTML-sensitive characters escaped, slashes and unicode left as-is).
     */
    public function toJson(): string
    {
        return json_encode(
            $this,
            JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_HEX_TAG | JSON_HEX_AMP,
        );
    }
}
