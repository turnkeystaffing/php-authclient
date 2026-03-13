<?php

declare(strict_types=1);

namespace Turnkey\AuthClient\Cache;

use Turnkey\AuthClient\CacheInterface;

class InMemoryCache implements CacheInterface
{
    /** @var array<string, array{value: mixed, expiresAt: float}> */
    private array $entries = [];

    public function __construct(
        private readonly int $maxSize = 1000,
    ) {
    }

    public function get(string $key): mixed
    {
        if (!isset($this->entries[$key])) {
            return null;
        }

        $entry = $this->entries[$key];
        if (microtime(true) > $entry['expiresAt']) {
            unset($this->entries[$key]);
            return null;
        }

        return $entry['value'];
    }

    public function set(string $key, mixed $value, int $ttlSeconds): void
    {
        $this->evictExpired();

        if (count($this->entries) >= $this->maxSize) {
            $this->evictOldest();
        }

        $this->entries[$key] = [
            'value' => $value,
            'expiresAt' => microtime(true) + $ttlSeconds,
        ];
    }

    public function delete(string $key): void
    {
        unset($this->entries[$key]);
    }

    private function evictExpired(): void
    {
        $now = microtime(true);
        foreach ($this->entries as $key => $entry) {
            if ($now > $entry['expiresAt']) {
                unset($this->entries[$key]);
            }
        }
    }

    private function evictOldest(): void
    {
        $oldestKey = null;
        $oldestTime = PHP_FLOAT_MAX;

        foreach ($this->entries as $key => $entry) {
            if ($entry['expiresAt'] < $oldestTime) {
                $oldestTime = $entry['expiresAt'];
                $oldestKey = $key;
            }
        }

        if ($oldestKey !== null) {
            unset($this->entries[$oldestKey]);
        }
    }
}