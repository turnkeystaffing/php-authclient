<?php

declare(strict_types=1);

namespace Turnkey\AuthClient\Cache;

use Psr\Log\LoggerInterface;
use Turnkey\AuthClient\CacheInterface;

/**
 * Wraps a primary cache with a fallback. When the primary throws,
 * operations fall through to the fallback and the primary is skipped
 * for a cooldown period to avoid repeated connection timeouts.
 *
 * On set, both primary and fallback are written (dual-write) so the fallback
 * is warm on failover. On delete, both are cleared. On get, only the active
 * cache is queried.
 */
class FallbackCache implements CacheInterface
{
    private float $primaryDownUntil = 0.0;

    public function __construct(
        private readonly CacheInterface $primary,
        private readonly CacheInterface $fallback,
        private readonly int $cooldownSeconds = 30,
        private readonly ?LoggerInterface $logger = null,
    ) {
    }

    public function get(string $key): mixed
    {
        if ($this->isPrimaryAvailable()) {
            try {
                return $this->primary->get($key);
            } catch (\Throwable $e) {
                $this->markPrimaryDown('get', $e);
            }
        }

        return $this->fallback->get($key);
    }

    public function set(string $key, mixed $value, int $ttlSeconds): void
    {
        // Always write to fallback to keep it warm for failover
        try {
            $this->fallback->set($key, $value, $ttlSeconds);
        } catch (\Throwable) {
        }

        if (!$this->isPrimaryAvailable()) {
            return;
        }

        try {
            $this->primary->set($key, $value, $ttlSeconds);
        } catch (\Throwable $e) {
            $this->markPrimaryDown('set', $e);
        }
    }

    public function delete(string $key): void
    {
        // Always delete from fallback
        try {
            $this->fallback->delete($key);
        } catch (\Throwable) {
        }

        if (!$this->isPrimaryAvailable()) {
            return;
        }

        try {
            $this->primary->delete($key);
        } catch (\Throwable $e) {
            $this->markPrimaryDown('delete', $e);
        }
    }

    private function isPrimaryAvailable(): bool
    {
        return microtime(true) >= $this->primaryDownUntil;
    }

    private function markPrimaryDown(string $operation, \Throwable $e): void
    {
        $this->primaryDownUntil = microtime(true) + $this->cooldownSeconds;
        $this->logger?->warning(sprintf('cache: primary %s failed, using fallback', $operation), [
            'error' => $e->getMessage(),
        ]);
    }
}
