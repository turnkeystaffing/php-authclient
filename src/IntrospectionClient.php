<?php

declare(strict_types=1);

namespace Turnkey\AuthClient;

use Psr\Log\LoggerInterface;
use Symfony\Contracts\HttpClient\HttpClientInterface;

class IntrospectionClient implements TokenValidatorInterface, IntrospectorInterface
{
    private const MAX_RESPONSE_BODY = 1048576; // 1 MB

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
        if (!str_starts_with($introspectionEndpoint, 'https://')) {
            $this->logger->warning('Introspection endpoint is not HTTPS', [
                'endpoint' => $introspectionEndpoint,
            ]);
        }
    }

    public function validateToken(string $token): Claims
    {
        $response = $this->introspect($token);
        return $response->toClaims();
    }

    public function introspect(string $token): IntrospectionResponse
    {
        $cacheKey = hash('sha256', $token);

        // Check cache
        if ($this->cache !== null) {
            $cached = $this->fromCacheValue($this->cache->get($cacheKey));
            if ($cached !== null) {
                if (!$cached->active) {
                    $this->cache->delete($cacheKey);
                } else {
                    return $cached;
                }
            }
        }

        try {
            $response = $this->doIntrospect($token);
        } catch (AuthClientError $e) {
            // Only fall back on network errors, not HTTP errors
            if ($e->getErrorType() === AuthClientError::INTROSPECTION_FAILED && $this->fallbackValidator !== null) {
                $this->logger->warning('Introspection network error, falling back to JWKS validation', [
                    'error' => $e->getMessage(),
                ]);
                $claims = $this->fallbackValidator->validateToken($token);

                return new IntrospectionResponse(
                    active: true,
                    clientId: $claims->clientId,
                    exp: $claims->expiresAt?->getTimestamp(),
                    sub: $claims->subject,
                    scope: implode(' ', $claims->scopes),
                );
            }
            throw $e;
        }

        // Cache response
        if ($this->cache !== null && $response->active) {
            $ttl = $this->cacheTtlSeconds;
            if ($response->exp !== null) {
                $remaining = $response->exp - time();
                if ($remaining > 0) {
                    $ttl = min($ttl, $remaining);
                }
            }
            $this->cache->set($cacheKey, $response, $ttl);
        }

        return $response;
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
                'body' => http_build_query(['token' => $token]),
            ]);

            $statusCode = $response->getStatusCode();
        } catch (\Throwable $e) {
            throw AuthClientError::introspectionFailed(
                "introspection request failed: {$e->getMessage()}",
                $e
            );
        }

        if ($statusCode < 200 || $statusCode >= 300) {
            throw AuthClientError::introspectionRejected(
                "introspection endpoint returned HTTP {$statusCode}"
            );
        }

        try {
            $body = $response->getContent();
            if (strlen($body) > self::MAX_RESPONSE_BODY) {
                throw AuthClientError::introspectionParse('response body exceeds maximum size');
            }

            $data = json_decode($body, true, 512, JSON_THROW_ON_ERROR);
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