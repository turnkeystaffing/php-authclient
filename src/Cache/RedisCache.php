<?php

declare(strict_types=1);

namespace Turnkey\AuthClient\Cache;

use Turnkey\AuthClient\IntrospectionCacheInterface;
use Turnkey\AuthClient\IntrospectionResponse;
use Turnkey\AuthClient\Redis\RedisClientInterface;

/**
 * Redis-backed introspection cache using RedisClientInterface.
 *
 * Key prefixing is handled by the underlying PrefixedClient,
 * matching the go-redis pattern where the cache only manages
 * its own key namespace ("introspection:") and the client adds
 * the application prefix (e.g. "myapp:introspection:<sha256>").
 */
class RedisCache implements IntrospectionCacheInterface
{
    private readonly string $keyNamespace;

    public function __construct(
        private readonly RedisClientInterface $redis,
        string $keyNamespace = 'introspection:',
    ) {
        $this->keyNamespace = $keyNamespace;
    }

    public function get(string $key): ?IntrospectionResponse
    {
        $data = $this->redis->get($this->keyNamespace . $key);
        if ($data === null) {
            return null;
        }

        $decoded = json_decode($data, true);
        if (!is_array($decoded)) {
            return null;
        }

        return IntrospectionResponse::fromArray($decoded);
    }

    public function set(string $key, IntrospectionResponse $response, int $ttlSeconds): void
    {
        $data = json_encode([
            'active' => $response->active,
            'client_id' => $response->clientId,
            'username' => $response->username,
            'token_type' => $response->tokenType,
            'exp' => $response->exp,
            'iat' => $response->iat,
            'nbf' => $response->nbf,
            'sub' => $response->sub,
            'aud' => $response->aud,
            'iss' => $response->iss,
            'scope' => $response->scope,
            'gty' => $response->grantType,
            'auth_time' => $response->authTime,
        ], JSON_THROW_ON_ERROR);

        $this->redis->set($this->keyNamespace . $key, $data, $ttlSeconds);
    }

    public function delete(string $key): void
    {
        $this->redis->del($this->keyNamespace . $key);
    }
}
