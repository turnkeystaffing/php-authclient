<?php

declare(strict_types=1);

namespace Turnkey\AuthClient;

use Firebase\JWT\JWK;
use Psr\Log\LoggerInterface;
use Symfony\Contracts\HttpClient\HttpClientInterface;

class JwksProvider
{
    private array $keys = [];
    private float $lastFetchTime = 0;
    private readonly int $refreshIntervalSeconds;
    private readonly float $httpTimeoutSeconds;

    public function __construct(
        private readonly string $jwksEndpoint,
        private readonly HttpClientInterface $httpClient,
        private readonly LoggerInterface $logger,
        int $refreshIntervalSeconds = 300,
        float $httpTimeoutSeconds = 10.0,
        bool $failFast = true,
    ) {
        $this->refreshIntervalSeconds = $refreshIntervalSeconds;
        $this->httpTimeoutSeconds = $httpTimeoutSeconds;

        if (!str_starts_with($jwksEndpoint, 'https://')) {
            $this->logger->warning('JWKS endpoint is not HTTPS', ['endpoint' => $jwksEndpoint]);
        }

        if ($failFast) {
            $this->refreshKeys();
        }
    }

    /**
     * Get the key set for JWT verification.
     *
     * @return array<string, \OpenSSLAsymmetricKey> Keyed by KID
     */
    public function getKeys(): array
    {
        $now = microtime(true);
        if (($now - $this->lastFetchTime) > $this->refreshIntervalSeconds) {
            $this->refreshKeys();
        }

        return $this->keys;
    }

    private function refreshKeys(): void
    {
        try {
            $response = $this->httpClient->request('GET', $this->jwksEndpoint, [
                'timeout' => $this->httpTimeoutSeconds,
                'max_redirects' => 0,
            ]);

            $statusCode = $response->getStatusCode();
            if ($statusCode !== 200) {
                throw new \RuntimeException("JWKS endpoint returned HTTP {$statusCode}");
            }

            $body = $response->getContent();
            $jwks = json_decode($body, true, 512, JSON_THROW_ON_ERROR);

            $this->keys = JWK::parseKeySet($jwks);
            $this->lastFetchTime = microtime(true);

            $this->logger->debug('JWKS keys refreshed', ['key_count' => count($this->keys)]);
        } catch (\Throwable $e) {
            if (empty($this->keys)) {
                throw AuthClientError::tokenUnverifiable("failed to fetch JWKS: {$e->getMessage()}", $e);
            }

            $this->logger->error('Failed to refresh JWKS keys, using cached keys', [
                'error' => $e->getMessage(),
            ]);
        }
    }
}
