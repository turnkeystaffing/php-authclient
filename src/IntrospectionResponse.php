<?php

declare(strict_types=1);

namespace Turnkey\AuthClient;

class IntrospectionResponse implements \JsonSerializable
{
    public function __construct(
        public readonly bool $active,
        public readonly ?string $clientId = null,
        public readonly ?string $username = null,
        public readonly ?string $tokenType = null,
        public readonly ?int $exp = null,
        public readonly ?int $iat = null,
        public readonly ?int $nbf = null,
        public readonly ?string $sub = null,
        public readonly ?string $aud = null,
        public readonly ?string $iss = null,
        public readonly ?string $scope = null,
        public readonly ?string $grantType = null,
        public readonly ?int $authTime = null,
    ) {
    }

    public static function fromArray(array $data): self
    {
        return new self(
            active: (bool) ($data['active'] ?? false),
            clientId: $data['client_id'] ?? null,
            username: $data['username'] ?? null,
            tokenType: $data['token_type'] ?? null,
            exp: isset($data['exp']) ? (int) $data['exp'] : null,
            iat: isset($data['iat']) ? (int) $data['iat'] : null,
            nbf: isset($data['nbf']) ? (int) $data['nbf'] : null,
            sub: $data['sub'] ?? null,
            aud: $data['aud'] ?? null,
            iss: $data['iss'] ?? null,
            scope: $data['scope'] ?? null,
            grantType: $data['gty'] ?? null,
            authTime: isset($data['auth_time']) ? (int) $data['auth_time'] : null,
        );
    }

    public function jsonSerialize(): array
    {
        return [
            'active' => $this->active,
            'client_id' => $this->clientId,
            'username' => $this->username,
            'token_type' => $this->tokenType,
            'exp' => $this->exp,
            'iat' => $this->iat,
            'nbf' => $this->nbf,
            'sub' => $this->sub,
            'aud' => $this->aud,
            'iss' => $this->iss,
            'scope' => $this->scope,
            'gty' => $this->grantType,
            'auth_time' => $this->authTime,
        ];
    }

    public function toClaims(): Claims
    {
        if (!$this->active) {
            throw AuthClientError::tokenInactive();
        }

        $clientId = $this->clientId ?? '';
        if ($clientId === '') {
            throw AuthClientError::missingClientId();
        }

        $scopes = $this->scope !== null ? explode(' ', $this->scope) : [];

        return new Claims(
            clientId: $clientId,
            scopes: array_values(array_filter($scopes, fn($s) => $s !== '')),
            username: $this->username,
            expiresAt: $this->exp !== null ? new \DateTimeImmutable('@' . $this->exp) : null,
            subject: $this->sub,
            audience: $this->aud !== null ? [$this->aud] : [],
            issuedAt: $this->iat !== null ? new \DateTimeImmutable('@' . $this->iat) : null,
            notBefore: $this->nbf !== null ? new \DateTimeImmutable('@' . $this->nbf) : null,
            grantType: $this->grantType,
            authTime: $this->authTime,
        );
    }
}
