<?php

declare(strict_types=1);

namespace Turnkey\AuthClient;

use Psr\Log\LoggerInterface;
use Symfony\Contracts\HttpClient\HttpClientInterface;
use Turnkey\AuthClient\Redis\RedisClientInterface;

class OAuthTokenProvider implements TokenProviderInterface
{
    private const MAX_EXPIRES_IN = 31_536_000; // 1 year
    private const REFRESH_THRESHOLD = 0.8;
    private const MAX_RESPONSE_BODY = 1_048_576; // 1 MB
    private const CACHE_KEY = 'oauth_token';

    private ?string $cachedToken = null;
    private ?float $tokenExpiresAt = null;
    private ?float $refreshAt = null;
    private bool $closed = false;

    public function __construct(
        private readonly string $tokenEndpoint,
        private readonly string $clientId,
        private readonly string $clientSecret,
        private readonly HttpClientInterface $httpClient,
        private readonly LoggerInterface $logger,
        private readonly array $scopes = [],
        private readonly float $httpTimeoutSeconds = 10.0,
        private readonly ?RedisClientInterface $redis = null,
        private readonly string $cacheKeyNamespace = 'token_provider:',
    ) {
        if (!str_starts_with($tokenEndpoint, 'https://')) {
            $this->logger->warning('Token endpoint is not HTTPS', ['endpoint' => $tokenEndpoint]);
        }
    }

    public function getToken(): string
    {
        if ($this->closed) {
            throw AuthClientError::tokenProviderClosed();
        }

        $now = microtime(true);

        // Check in-memory cache first
        if ($this->cachedToken !== null && $this->tokenExpiresAt !== null && $now < $this->refreshAt) {
            return $this->cachedToken;
        }

        // Check Redis cache (for php-fpm: token persists across requests)
        if ($this->cachedToken === null && $this->redis !== null) {
            $this->loadFromRedis($now);
        }

        // Return in-memory cached token if still before refresh threshold
        if ($this->cachedToken !== null && $this->tokenExpiresAt !== null && $now < $this->refreshAt) {
            return $this->cachedToken;
        }

        // If we have a valid (not expired) token but past refresh threshold, try refresh
        // but return the existing token on failure
        if ($this->cachedToken !== null && $this->tokenExpiresAt !== null && $now < $this->tokenExpiresAt) {
            try {
                $this->fetchToken();
            } catch (\Throwable $e) {
                $this->logger->warning('Proactive token refresh failed, using cached token', [
                    'error' => $e->getMessage(),
                ]);
                return $this->cachedToken;
            }
            return $this->cachedToken;
        }

        // No valid token - must fetch
        $this->fetchToken();
        return $this->cachedToken;
    }

    public function close(): void
    {
        $this->closed = true;
        $this->cachedToken = null;
        $this->tokenExpiresAt = null;
        $this->refreshAt = null;
    }

    private function loadFromRedis(float $now): void
    {
        $data = $this->redis->get($this->cacheKeyNamespace . self::CACHE_KEY);
        if ($data === null) {
            return;
        }

        $decoded = json_decode($data, true);
        if (!is_array($decoded) || !isset($decoded['token'], $decoded['expires_at'])) {
            return;
        }

        $expiresAt = (float) $decoded['expires_at'];
        if ($now >= $expiresAt) {
            $this->redis->del($this->cacheKeyNamespace . self::CACHE_KEY);
            return;
        }

        $this->cachedToken = (string) $decoded['token'];
        $this->tokenExpiresAt = $expiresAt;
        // Recalculate refresh threshold from remaining lifetime
        $originalLifetime = $expiresAt - (float) ($decoded['issued_at'] ?? $now);
        $this->refreshAt = $expiresAt - ($originalLifetime * (1 - self::REFRESH_THRESHOLD));
    }

    private function saveToRedis(string $token, float $issuedAt, float $expiresAt): void
    {
        if ($this->redis === null) {
            return;
        }

        $ttl = (int) ceil($expiresAt - $issuedAt);
        if ($ttl <= 0) {
            return;
        }

        $data = json_encode([
            'token' => $token,
            'issued_at' => $issuedAt,
            'expires_at' => $expiresAt,
        ], JSON_THROW_ON_ERROR);

        $this->redis->set($this->cacheKeyNamespace . self::CACHE_KEY, $data, $ttl);
    }

    private function fetchToken(): void
    {
        // RFC 6749 Section 2.3.1: percent-encode client credentials
        $encodedId = rawurlencode($this->clientId);
        $encodedSecret = rawurlencode($this->clientSecret);

        $body = ['grant_type' => 'client_credentials'];
        if (!empty($this->scopes)) {
            $body['scope'] = implode(' ', $this->scopes);
        }

        try {
            $response = $this->httpClient->request('POST', $this->tokenEndpoint, [
                'timeout' => $this->httpTimeoutSeconds,
                'max_redirects' => 0,
                'headers' => [
                    'Authorization' => 'Basic ' . base64_encode("{$encodedId}:{$encodedSecret}"),
                    'Content-Type' => 'application/x-www-form-urlencoded',
                ],
                'body' => http_build_query($body),
            ]);

            $statusCode = $response->getStatusCode();
            if ($statusCode < 200 || $statusCode >= 300) {
                throw new \RuntimeException("token endpoint returned HTTP {$statusCode}");
            }

            $content = $response->getContent();
            if (strlen($content) > self::MAX_RESPONSE_BODY) {
                throw new \RuntimeException('response body exceeds maximum size');
            }

            $data = json_decode($content, true, 512, JSON_THROW_ON_ERROR);
        } catch (\Throwable $e) {
            throw AuthClientError::introspectionFailed(
                "token request failed: {$e->getMessage()}",
                $e
            );
        }

        $accessToken = $data['access_token'] ?? '';
        $tokenType = $data['token_type'] ?? '';
        $expiresIn = (int) ($data['expires_in'] ?? 0);

        if (strcasecmp($tokenType, 'Bearer') !== 0) {
            throw AuthClientError::tokenInvalid("unexpected token_type: {$tokenType}");
        }

        if ($expiresIn <= 0) {
            throw AuthClientError::tokenInvalid('expires_in must be positive');
        }

        if ($expiresIn > self::MAX_EXPIRES_IN) {
            throw AuthClientError::tokenInvalid(
                sprintf('expires_in %d exceeds maximum %d', $expiresIn, self::MAX_EXPIRES_IN)
            );
        }

        if ($expiresIn > 86400) {
            $this->logger->warning('Token lifetime exceeds 24 hours', ['expires_in' => $expiresIn]);
        }

        $now = microtime(true);
        $this->cachedToken = $accessToken;
        $this->tokenExpiresAt = $now + $expiresIn;
        $this->refreshAt = $now + ($expiresIn * self::REFRESH_THRESHOLD);

        $this->saveToRedis($accessToken, $now, $this->tokenExpiresAt);
    }
}
