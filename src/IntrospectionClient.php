<?php

declare(strict_types=1);

namespace Turnkey\AuthClient;

use Psr\Log\LoggerInterface;
use Symfony\Contracts\HttpClient\HttpClientInterface;

class IntrospectionClient implements TokenValidatorInterface, IntrospectorInterface
{
    private const MAX_RESPONSE_BODY = 1048576; // 1 MB

    /**
     * @param int $cacheTtlSeconds Maximum cache duration. The effective TTL is min(this, remaining token lifetime);
     *                             0 or less means "use the token's remaining lifetime".
     */
    public function __construct(
        private readonly string $introspectionEndpoint,
        private readonly string $clientId,
        private readonly string $clientSecret,
        private readonly HttpClientInterface $httpClient,
        private readonly LoggerInterface $logger,
        private readonly ?CacheInterface $cache = null,
        private readonly int $cacheTtlSeconds = 300,
        private readonly ?TokenValidatorInterface $fallbackValidator = null,
        private readonly float $httpTimeoutSeconds = 10.0,
    ) {
        if ($introspectionEndpoint === '') {
            throw new \InvalidArgumentException('authclient: introspection endpoint cannot be empty');
        }
        if ($clientId === '') {
            throw new \InvalidArgumentException('authclient: introspection client ID cannot be empty');
        }
        if ($clientSecret === '') {
            throw new \InvalidArgumentException('authclient: introspection client secret cannot be empty');
        }

        if (!str_starts_with(strtolower($introspectionEndpoint), 'https://')) {
            $this->logger->warning('Introspection endpoint is not HTTPS — credentials sent in plaintext', [
                'endpoint' => UrlSanitizer::sanitize($introspectionEndpoint),
            ]);
        }
    }

    /**
     * Validate a token via introspection. Falls back to the fallback validator
     * (typically JwksValidator) only on network errors — never on HTTP error
     * responses or unparseable bodies.
     */
    public function validateToken(string $token): Claims
    {
        try {
            $response = $this->introspect($token);
        } catch (AuthClientError $e) {
            if ($e->getErrorType() === AuthClientError::INTROSPECTION_FAILED && $this->fallbackValidator !== null) {
                $this->logger->warning('Introspection endpoint unreachable, falling back to JWKS validation', [
                    'endpoint' => UrlSanitizer::sanitize($this->introspectionEndpoint),
                ]);

                return $this->fallbackValidator->validateToken($token);
            }
            throw $e;
        }

        return $response->toClaims();
    }

    public function introspect(string $token): IntrospectionResponse
    {
        if (strlen($token) > self::MAX_BEARER_TOKEN_LENGTH) {
            throw AuthClientError::tokenOversized(
                sprintf('token length %d exceeds maximum %d', strlen($token), self::MAX_BEARER_TOKEN_LENGTH)
            );
        }

        $cacheKey = 'introspect:' . hash('sha256', $token);

        if ($this->cache !== null) {
            $cached = $this->cacheGet($cacheKey);
            if ($cached !== null) {
                if ($cached->exp !== null && $cached->exp > 0 && time() >= $cached->exp) {
                    $this->cacheDelete($cacheKey);
                } elseif ($cached->active) {
                    return $cached;
                }
            }
        }

        $response = $this->doIntrospect($token);

        if ($this->cache === null) {
            return $response;
        }

        // Inactive tokens: delete stale cache entry, do NOT cache
        if (!$response->active) {
            $this->cacheDelete($cacheKey);
            return $response;
        }

        // TTL = min(configured, remaining token lifetime); unconfigured → remaining lifetime
        $ttl = $this->cacheTtlSeconds;
        if ($response->exp !== null && $response->exp > 0) {
            $remaining = $response->exp - time();
            if ($ttl <= 0 || $remaining < $ttl) {
                $ttl = $remaining;
            }
        }

        if ($ttl > 0) {
            try {
                $this->cache->set($cacheKey, $response, $ttl);
            } catch (\Throwable $e) {
                $this->logger->warning('Failed to cache introspection response', ['error' => $e->getMessage()]);
            }
        }

        return $response;
    }

    private function cacheGet(string $key): ?IntrospectionResponse
    {
        try {
            return $this->fromCacheValue($this->cache?->get($key));
        } catch (\Throwable $e) {
            $this->logger->warning('Failed to read introspection cache', ['error' => $e->getMessage()]);
            return null;
        }
    }

    private function cacheDelete(string $key): void
    {
        try {
            $this->cache?->delete($key);
        } catch (\Throwable $e) {
            $this->logger->warning('Failed to delete introspection cache entry', ['error' => $e->getMessage()]);
        }
    }

    private function fromCacheValue(mixed $value): ?IntrospectionResponse
    {
        if ($value instanceof IntrospectionResponse) {
            return $value;
        }

        if (is_array($value)) {
            return IntrospectionResponse::fromArray($value);
        }

        return null;
    }

    private function doIntrospect(string $token): IntrospectionResponse
    {
        // RFC 6749 Section 2.3.1: percent-encode client credentials
        $encodedId = rawurlencode($this->clientId);
        $encodedSecret = rawurlencode($this->clientSecret);

        try {
            $response = $this->httpClient->request('POST', $this->introspectionEndpoint, [
                'timeout' => $this->httpTimeoutSeconds,
                'max_redirects' => 0,
                'headers' => [
                    'Authorization' => 'Basic ' . base64_encode("{$encodedId}:{$encodedSecret}"),
                    'Content-Type' => 'application/x-www-form-urlencoded',
                ],
                'body' => http_build_query(['token' => $token, 'token_type_hint' => 'access_token']),
            ]);

            $statusCode = $response->getStatusCode();
        } catch (\Throwable $e) {
            throw AuthClientError::introspectionFailed(
                "introspection request failed: {$e->getMessage()}",
                $e
            );
        }

        if ($statusCode !== 200) {
            throw AuthClientError::introspectionRejected(
                "introspection endpoint returned HTTP {$statusCode}"
            );
        }

        try {
            $body = $response->getContent(false);
            if (strlen($body) > self::MAX_RESPONSE_BODY) {
                throw AuthClientError::introspectionParse('response body exceeds maximum size');
            }
            if ($body === '') {
                throw AuthClientError::introspectionParse('empty introspection response');
            }

            $data = json_decode($body, true, 512, JSON_THROW_ON_ERROR);
            if (!is_array($data)) {
                throw AuthClientError::introspectionParse('introspection response is not a JSON object');
            }
        } catch (AuthClientError $e) {
            throw $e;
        } catch (\Throwable $e) {
            throw AuthClientError::introspectionParse(
                "failed to parse introspection response: {$e->getMessage()}",
                $e
            );
        }

        return IntrospectionResponse::fromArray($data);
    }
}