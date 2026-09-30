<?php

declare(strict_types=1);

namespace Turnkey\AuthClient\Discovery;

/**
 * Strict field extraction helpers for decoding manifests (equivalent of Go's
 * yaml KnownFields(true) / json DisallowUnknownFields()).
 *
 * @internal
 */
final class ManifestFields
{
    /**
     * @param string[] $allowed
     * @return array<string, mixed>
     * @throws ManifestException
     */
    public static function mapping(mixed $data, string $path, array $allowed): array
    {
        if (!is_array($data) || ($data !== [] && array_is_list($data))) {
            throw new ManifestException(sprintf('%s must be a mapping', $path));
        }

        foreach (array_keys($data) as $key) {
            if (!in_array($key, $allowed, true)) {
                throw new ManifestException(sprintf('%s: unknown field "%s"', $path, $key));
            }
        }

        return $data;
    }

    /**
     * @param array<string, mixed> $data
     * @return list<mixed>
     * @throws ManifestException
     */
    public static function sequence(array $data, string $field, string $path): array
    {
        $value = $data[$field] ?? null;
        if ($value === null) {
            return [];
        }
        if (!is_array($value) || !array_is_list($value)) {
            throw new ManifestException(sprintf('%s: field "%s" must be a list', $path, $field));
        }

        return $value;
    }

    /**
     * @param array<string, mixed> $data
     * @throws ManifestException
     */
    public static function string(array $data, string $field, string $path): string
    {
        $value = $data[$field] ?? null;
        if ($value === null) {
            return '';
        }

        return self::scalar($value, sprintf('%s: field "%s"', $path, $field));
    }

    /**
     * @throws ManifestException
     */
    public static function scalar(mixed $value, string $path): string
    {
        if (is_string($value)) {
            return $value;
        }
        if (is_int($value) || is_float($value)) {
            return (string) $value;
        }

        throw new ManifestException(sprintf('%s must be a string', $path));
    }
}
