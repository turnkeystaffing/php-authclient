<?php

declare(strict_types=1);

namespace Turnkey\AuthClient;

use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use Psr\Log\LoggerInterface;

class JwksValidator implements TokenValidatorInterface
{
    private const MAX_TOKEN_LENGTH = 4096;
    private const ALLOWED_ALGORITHMS = ['RS256', 'RS384', 'RS512'];

    public function __construct(
        private readonly JwksProvider $jwksProvider,
        private readonly string $issuer,
        private readonly LoggerInterface $logger,
    ) {
    }

    public function validateToken(string $token): Claims
    {
        if (strlen($token) > self::MAX_TOKEN_LENGTH) {
            throw AuthClientError::tokenOversized(
                sprintf('token length %d exceeds maximum %d', strlen($token), self::MAX_TOKEN_LENGTH)
            );
        }

        $keys = $this->jwksProvider->getKeys();
        if (empty($keys)) {
            throw AuthClientError::tokenUnverifiable('no JWKS keys available');
        }

        // Check algorithm from header before decoding
        $parts = explode('.', $token);
        if (count($parts) !== 3) {
            throw AuthClientError::tokenMalformed('token does not have three parts');
        }

        $headerJson = base64_decode(strtr($parts[0], '-_', '+/'), true);
        if ($headerJson === false) {
            throw AuthClientError::tokenMalformed('unable to decode token header');
        }

        $header = json_decode($headerJson, false);
        if ($header === null) {
            throw AuthClientError::tokenMalformed('unable to parse token header');
        }

        $alg = $header->alg ?? '';
        if (!in_array($alg, self::ALLOWED_ALGORITHMS, true)) {
            throw AuthClientError::algorithmNotAllowed(
                sprintf('algorithm "%s" is not allowed, must be one of: %s', $alg, implode(', ', self::ALLOWED_ALGORITHMS))
            );
        }

        try {
            $payload = JWT::decode($token, $keys);
        } catch (\Firebase\JWT\ExpiredException $e) {
            throw AuthClientError::tokenExpired($e->getMessage(), $e);
        } catch (\Firebase\JWT\BeforeValidException $e) {
            throw AuthClientError::tokenNotYetValid($e->getMessage(), $e);
        } catch (\Firebase\JWT\SignatureInvalidException $e) {
            throw AuthClientError::tokenUnverifiable($e->getMessage(), $e);
        } catch (\UnexpectedValueException $e) {
            throw AuthClientError::tokenMalformed($e->getMessage(), $e);
        } catch (\Throwable $e) {
            throw AuthClientError::tokenInvalid($e->getMessage(), $e);
        }

        // Verify issuer
        $tokenIssuer = $payload->iss ?? '';
        if ($tokenIssuer !== $this->issuer) {
            throw AuthClientError::tokenInvalid(
                sprintf('invalid issuer: expected "%s", got "%s"', $this->issuer, $tokenIssuer)
            );
        }

        return Claims::fromJwtPayload($payload);
    }
}
