<?php

declare(strict_types=1);

namespace Turnkey\AuthClient;

/**
 * Claims extracted from a validated token.
 *
 * WARNING: Email and Username are NOT sanitized. Consumers MUST sanitize
 * these values before using in SQL queries, HTML output, or log messages.
 */
class Claims
{
    public function __construct(
        public readonly string $clientId,
        public readonly array $scopes = [],
        public readonly ?string $userId = null,
        public readonly ?string $email = null,
        public readonly ?string $username = null,
        public readonly ?\DateTimeImmutable $expiresAt = null,
        public readonly ?string $subject = null,
        public readonly array $audience = [],
        public readonly ?\DateTimeImmutable $issuedAt = null,
        public readonly ?\DateTimeImmutable $notBefore = null,
    ) {
    }

    public function deepCopy(): self
    {
        return new self(
            clientId: $this->clientId,
            scopes: $this->scopes,
            userId: $this->userId,
            email: $this->email,
            username: $this->username,
            expiresAt: $this->expiresAt,
            subject: $this->subject,
            audience: $this->audience,
            issuedAt: $this->issuedAt,
            notBefore: $this->notBefore,
        );
    }

    public static function fromJwtPayload(object $payload): self
    {
        $clientId = $payload->client_id ?? $payload->cid ?? '';
        if ($clientId === '') {
            throw AuthClientError::missingClientId();
        }

        $scopes = [];
        if (isset($payload->scope)) {
            $scopes = is_string($payload->scope) ? explode(' ', $payload->scope) : (array) $payload->scope;
        } elseif (isset($payload->scp)) {
            $scopes = is_string($payload->scp) ? explode(' ', $payload->scp) : (array) $payload->scp;
        }

        return new self(
            clientId: (string) $clientId,
            scopes: array_values(array_filter($scopes, fn($s) => $s !== '')),
            userId: isset($payload->user_id) ? (string) $payload->user_id : null,
            email: isset($payload->email) ? (string) $payload->email : null,
            username: isset($payload->username) ? (string) $payload->username : null,
            expiresAt: isset($payload->exp) ? new \DateTimeImmutable('@' . (int) $payload->exp) : null,
            subject: isset($payload->sub) ? (string) $payload->sub : null,
            audience: isset($payload->aud) ? (array) $payload->aud : [],
            issuedAt: isset($payload->iat) ? new \DateTimeImmutable('@' . (int) $payload->iat) : null,
            notBefore: isset($payload->nbf) ? new \DateTimeImmutable('@' . (int) $payload->nbf) : null,
        );
    }
}
