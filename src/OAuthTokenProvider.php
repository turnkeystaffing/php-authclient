<?php

declare(strict_types=1);

namespace Turnkey\AuthClient;

use Psr\Log\LoggerInterface;
use Symfony\Contracts\HttpClient\HttpClientInterface;

class OAuthTokenProvider implements TokenProviderInterface
{
    private const MAX_EXPIRES_IN = 31_536_000; // 1 year
    private const REFRESH_THRESHOLD = 0.8;
    private const MAX_RESPONSE_BODY = 1_048_576; // 1 MB

    private readonly string $cacheKey;
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
        private readonly ?CacheInterface $cache = null,
        private readonly string $cacheKeyNamespace = 'token_provider:',
    ) {
        if ($clientId === '') {
            throw new \InvalidArgumentException('authclient: token provider: client ID is required');
        }
        if ($clientSecret === '') {
            throw new \InvalidArgumentException('authclient: token provider: client secret is required');
        }
        if ($tokenEndpoint === '') {
            throw new \InvalidArgumentException('authclient: token provider: token URL is required');
        }
        $parsed = parse_url($tokenEndpoint);
        if ($parsed === false) {
            throw new \InvalidArgumentException('authclient: token provider: invalid token URL');
        }
        $scheme = strtolower($parsed['scheme'] ?? '');
        if ($scheme !== 'http' && $scheme !== 'https') {
            throw new \InvalidArgumentException(
                sprintf('authclient: token provider: token URL scheme must be http or https, got "%s"', $scheme),
            );
        }
        if (($parsed['host'] ?? '') === '') {
            throw new \InvalidArgumentException('authclient: token provider: token URL must include a host');
        }

        if ($scheme === 'http') {
            $this->logger->warning(
                'authclient: token provider: token URL uses plaintext HTTP — credentials will be transmitted without TLS',
                ['token_url' => UrlSanitizer::sanitize($tokenEndpoint)],
            );
        }

        // Derive a unique cache key from client identity + requested scopes
        // so multiple providers with different configs don't collide.
        $sortedScopes = $this->scopes;
        sort($sortedScopes);
        $this->cacheKey = 'token:' . hash('sha256', $this->clientId . "\0" . implode(' ', $sortedScopes));
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

        // Check persistent cache (for php-fpm: token persists across requests)
        if ($this->cachedToken === null && $this->cache !== null) {
            $this->loadFromCache($now);
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

    private function loadFromCache(float $now): void
    {
        $data = $this->cache->get($this->cacheKeyNamespace . $this->cacheKey);
        if (!is_array($data) || !isset($data['token'], $data['expires_at'])) {
            return;
        }

        $expiresAt = (float) $data['expires_at'];
        if ($now >= $expiresAt) {
            $this->cache->delete($this->cacheKeyNamespace . $this->cacheKey);
            return;
        }

        $this->cachedToken = (string) $data['token'];
        $this->tokenExpiresAt = $expiresAt;
        // Recalculate refresh threshold from remaining lifetime
        $originalLifetime = $expiresAt - (float) ($data['issued_at'] ?? $now);
        $this->refreshAt = $expiresAt - ($originalLifetime * (1 - self::REFRESH_THRESHOLD));
    }

    private function saveToCache(string $token, float $issuedAt, float $expiresAt): void
    {
        if ($this->cache === null) {
            return;
        }

        $ttl = (int) ceil($expiresAt - $issuedAt);
        if ($ttl <= 0) {
            return;
        }

        $this->cache->set($this->cacheKeyNamespace . $this->cacheKey, [
            'token' => $token,
            'issued_at' => $issuedAt,
            'expires_at' => $expiresAt,
        ], $ttl);
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
                    'Accept' => 'application/json',
                ],
                'body' => http_build_query($body),
            ]);

            // Do NOT echo the response body — include only the status code
            $statusCode = $response->getStatusCode();
            if ($statusCode !== 200) {
                throw new \RuntimeException("token request failed with status {$statusCode}");
            }

            $content = $response->getContent(false);
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

        if (!is_array($data)) {
            throw AuthClientError::tokenInvalid('invalid token response format');
        }

        $accessToken = is_string($data['access_token'] ?? null) ? $data['access_token'] : '';
        $tokenType = is_string($data['token_type'] ?? null) ? $data['token_type'] : '';
        $expiresIn = (int) ($data['expires_in'] ?? 0);
        $grantedScope = is_string($data['scope'] ?? null) ? $data['scope'] : '';

        if ($accessToken === '') {
            throw AuthClientError::tokenInvalid('empty access_token in response');
        }

        // Do NOT echo the server-provided token_type — it is response body data
        if (strcasecmp($tokenType, 'Bearer') !== 0) {
            throw AuthClientError::tokenInvalid('unsupported token_type, expected Bearer');
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

        // Scopes are unordered sets per RFC 6749 Section 3.3
        $requestedScope = implode(' ', $this->scopes);
        if ($requestedScope !== '' && $grantedScope !== '' && !self::scopeSetsEqual($requestedScope, $grantedScope)) {
            $this->logger->warning('Granted scope differs from requested', [
                'requested' => $requestedScope,
                'granted' => $grantedScope,
            ]);
        }

        $now = microtime(true);
        $this->cachedToken = $accessToken;
        $this->tokenExpiresAt = $now + $expiresIn;
        $this->refreshAt = $now + ($expiresIn * self::REFRESH_THRESHOLD);

        $this->saveToCache($accessToken, $now, $this->tokenExpiresAt);
    }

    private static function scopeSetsEqual(string $a, string $b): bool
    {
        $as = preg_split('/\s+/', trim($a), -1, PREG_SPLIT_NO_EMPTY) ?: [];
        $bs = preg_split('/\s+/', trim($b), -1, PREG_SPLIT_NO_EMPTY) ?: [];
        sort($as);
        sort($bs);

        return $as === $bs;
    }
}
