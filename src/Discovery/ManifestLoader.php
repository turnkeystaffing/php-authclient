<?php

declare(strict_types=1);

namespace Turnkey\AuthClient\Discovery;

use Symfony\Component\Yaml\Exception\ParseException;
use Symfony\Component\Yaml\Yaml;

/**
 * Loads, strictly parses and validates scope manifests from YAML or JSON.
 */
final class ManifestLoader
{
    /** Maximum manifest payload size in bytes (10 MB) — DoS protection. */
    public const MAX_SIZE = 10 * 1024 * 1024;

    /**
     * Read, parse and validate a manifest file. Format is detected by extension:
     * .yaml/.yml for YAML, .json for JSON (case-insensitive).
     *
     * Security: the path is used as-is. Callers must sanitize user-supplied paths
     * to prevent directory traversal. Error messages may contain the file path.
     *
     * @throws ManifestException
     */
    public static function fromFile(string $path): ScopeManifest
    {
        $ext = strtolower(pathinfo($path, PATHINFO_EXTENSION));
        $format = match ($ext) {
            'yaml', 'yml' => 'yaml',
            'json' => 'json',
            default => throw new ManifestException(
                sprintf('unsupported file extension "%s"; use .yaml, .yml, or .json', $ext === '' ? '' : '.' . $ext),
            ),
        };

        if (!is_file($path) || !is_readable($path)) {
            throw new ManifestException(sprintf('opening manifest file: %s is not a readable file', $path));
        }

        $data = @file_get_contents($path, false, null, 0, self::MAX_SIZE + 1);
        if ($data === false) {
            throw new ManifestException(sprintf('reading manifest: failed to read %s', $path));
        }

        return self::fromString($data, $format);
    }

    /**
     * Parse and validate a manifest from a string. Format must be "yaml" or "json".
     *
     * @throws ManifestException
     */
    public static function fromString(string $data, string $format): ScopeManifest
    {
        if (strlen($data) > self::MAX_SIZE) {
            throw new ManifestException(sprintf('manifest exceeds maximum size of %d bytes', self::MAX_SIZE));
        }

        $format = strtolower($format);
        $decoded = match ($format) {
            'yaml' => self::decodeYaml($data),
            'json' => self::decodeJson($data),
            '' => throw new ManifestException('format is required; use "yaml" or "json"'),
            default => throw new ManifestException(sprintf('unsupported format "%s"; use "yaml" or "json"', $format)),
        };

        $label = $format === 'yaml' ? 'YAML' : 'JSON';
        try {
            $manifest = ScopeManifest::fromArray($decoded);
        } catch (ManifestValidationException $e) {
            throw $e;
        } catch (ManifestException $e) {
            throw new ManifestException(sprintf('parsing %s manifest: %s', $label, $e->getMessage()), 0, $e);
        }

        ManifestValidator::validate($manifest);

        return $manifest;
    }

    private static function decodeYaml(string $data): mixed
    {
        if (trim($data) === '') {
            throw new ManifestException('parsing YAML manifest: empty document');
        }

        try {
            return Yaml::parse($data, Yaml::PARSE_EXCEPTION_ON_INVALID_TYPE);
        } catch (ParseException $e) {
            throw new ManifestException(sprintf('parsing YAML manifest: %s', $e->getMessage()), 0, $e);
        }
    }

    private static function decodeJson(string $data): mixed
    {
        if (trim($data) === '') {
            throw new ManifestException('parsing JSON manifest: empty document');
        }

        try {
            return json_decode($data, true, 64, JSON_THROW_ON_ERROR);
        } catch (\JsonException $e) {
            throw new ManifestException(sprintf('parsing JSON manifest: %s', $e->getMessage()), 0, $e);
        }
    }
}
