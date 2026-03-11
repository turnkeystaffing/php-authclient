<?php

declare(strict_types=1);

namespace Turnkey\AuthClient;

use RuntimeException;

class AuthClientError extends RuntimeException
{
    public const TOKEN_OVERSIZED = 'token_oversized';
    public const TOKEN_MALFORMED = 'token_malformed';
    public const TOKEN_EXPIRED = 'token_expired';
    public const TOKEN_NOT_YET_VALID = 'token_not_yet_valid';
    public const TOKEN_UNVERIFIABLE = 'token_unverifiable';
    public const TOKEN_INVALID = 'token_invalid';
    public const ALGORITHM_NOT_ALLOWED = 'algorithm_not_allowed';
    public const MISSING_CLIENT_ID = 'missing_client_id';
    public const INTROSPECTION_FAILED = 'introspection_failed';
    public const INTROSPECTION_REJECTED = 'introspection_rejected';
    public const INTROSPECTION_PARSE = 'introspection_parse';
    public const TOKEN_INACTIVE = 'token_inactive';
    public const TOKEN_PROVIDER_CLOSED = 'token_provider_closed';

    private string $errorType;

    public function __construct(string $errorType, string $message = '', ?\Throwable $previous = null)
    {
        $this->errorType = $errorType;
        parent::__construct($message ?: $errorType, 0, $previous);
    }

    public function getErrorType(): string
    {
        return $this->errorType;
    }

    public static function tokenOversized(string $message = 'token exceeds maximum length'): self
    {
        return new self(self::TOKEN_OVERSIZED, $message);
    }

    public static function tokenMalformed(string $message = 'token is malformed', ?\Throwable $previous = null): self
    {
        return new self(self::TOKEN_MALFORMED, $message, $previous);
    }

    public static function tokenExpired(string $message = 'token has expired', ?\Throwable $previous = null): self
    {
        return new self(self::TOKEN_EXPIRED, $message, $previous);
    }

    public static function tokenNotYetValid(string $message = 'token is not yet valid', ?\Throwable $previous = null): self
    {
        return new self(self::TOKEN_NOT_YET_VALID, $message, $previous);
    }

    public static function tokenUnverifiable(string $message = 'token signature cannot be verified', ?\Throwable $previous = null): self
    {
        return new self(self::TOKEN_UNVERIFIABLE, $message, $previous);
    }

    public static function tokenInvalid(string $message = 'token is invalid', ?\Throwable $previous = null): self
    {
        return new self(self::TOKEN_INVALID, $message, $previous);
    }

    public static function algorithmNotAllowed(string $message = 'algorithm not allowed'): self
    {
        return new self(self::ALGORITHM_NOT_ALLOWED, $message);
    }

    public static function missingClientId(string $message = 'token missing required client_id claim'): self
    {
        return new self(self::MISSING_CLIENT_ID, $message);
    }

    public static function introspectionFailed(string $message = 'introspection request failed', ?\Throwable $previous = null): self
    {
        return new self(self::INTROSPECTION_FAILED, $message, $previous);
    }

    public static function introspectionRejected(string $message = 'introspection endpoint returned error'): self
    {
        return new self(self::INTROSPECTION_REJECTED, $message);
    }

    public static function introspectionParse(string $message = 'failed to parse introspection response', ?\Throwable $previous = null): self
    {
        return new self(self::INTROSPECTION_PARSE, $message, $previous);
    }

    public static function tokenInactive(string $message = 'token is not active'): self
    {
        return new self(self::TOKEN_INACTIVE, $message);
    }

    public static function tokenProviderClosed(string $message = 'token provider is closed'): self
    {
        return new self(self::TOKEN_PROVIDER_CLOSED, $message);
    }
}
