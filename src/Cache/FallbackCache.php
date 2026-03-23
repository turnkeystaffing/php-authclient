<?php

declare(strict_types=1);

namespace Turnkey\AuthClient\Cache;

use Turnkey\AuthClient\CacheInterface;

/**
 * Wraps a primary cache with a fallback. When the primary throws,
 * operations fall through to the fallback and the primary is skipped
 * for a cooldown period to avoid repeated connection timeouts.
 */
class FallbackCache implements CacheInterface
{
    private float $primaryDownUntil = 0.0;

    public function __construct(
        private readonly CacheInterface $primary,
        private readonly CacheInterface $fallback,
        private readonly int $cooldownSeconds = 30,
    ) {
    }

    public function get(string $key): mixed
    {
        if ($this->isPrimaryAvailable()) {
            try {
                return $this->primary->get($key);
            } catch (\Throwable) {
                $this->markPrimaryDown();
            }
        }

        return $this->fallback->get($key);
    }

    public function set(string $key, mixed $value, int $ttlSeconds): void
    {
        if ($this->isPrimaryAvailable()) {
            try {
                $this->primary->set($key, $value, $ttlSeconds);
                return;
            } catch (\Throwable) {
                $this->markPrimaryDown();
            }
        }

        $this->fallback->set($key, $value, $ttlSeconds);
    }

    public function delete(string $key): void
    {
        if ($this->isPrimaryAvailable()) {
            try {
                $this->primary->delete($key);
                return;
            } catch (\Throwable) {
                $this->markPrimaryDown();
            }
        }

        $this->fallback->delete($key);
    }

    private function isPrimaryAvailable(): bool
    {
        return microtime(true) >= $this->primaryDownUntil;
    }

    private function markPrimaryDown(): void
    {
        $this->primaryDownUntil = microtime(true) + $this->cooldownSeconds;
    }
}