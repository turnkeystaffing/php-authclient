<?php

declare(strict_types=1);

namespace Turnkey\AuthClient\Middleware;

use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Turnkey\AuthClient\AuthClientError;
use Turnkey\AuthClient\Claims;
use Turnkey\AuthClient\TokenValidatorInterface;

class BearerAuthMiddleware
{
    public const CLAIMS_ATTRIBUTE = 'auth_claims';

    /** @var null|callable(AuthClientError, Request, int, string, string): ?Response */
    private $errorHandler;

    /**
     * @param null|callable(AuthClientError $error, Request $request, int $statusCode, string $errorCode, string $errorDescription): ?Response $errorHandler
     *        Custom error response builder. Returning null falls back to the default RFC 6750 JSON response.
     */
    public function __construct(
        private readonly TokenValidatorInterface $validator,
        ?callable $errorHandler = null,
    ) {
        $this->errorHandler = $errorHandler;
    }

    public function onKernelRequest(RequestEvent $event): void
    {
        if (!$event->isMainRequest()) {
            return;
        }

        $request = $event->getRequest();
        $authHeader = (string) $request->headers->get('Authorization', '');

        if ($authHeader === '') {
            $this->reject($event, AuthClientError::tokenMalformed('missing authorization header'), 'invalid_request', 'Missing authorization header');
            return;
        }

        if (strlen($authHeader) < 7 || strcasecmp(substr($authHeader, 0, 7), 'Bearer ') !== 0) {
            $this->reject($event, AuthClientError::tokenMalformed('invalid authorization header format'), 'invalid_request', 'Invalid authorization header format');
            return;
        }

        $token = trim(substr($authHeader, 7));
        if ($token === '') {
            $this->reject($event, AuthClientError::tokenMalformed('empty bearer token'), 'invalid_request', 'Empty bearer token');
            return;
        }

        if (strlen($token) > TokenValidatorInterface::MAX_BEARER_TOKEN_LENGTH) {
            $this->reject($event, AuthClientError::tokenOversized(), 'invalid_request', 'Bearer token exceeds maximum length');
            return;
        }

        try {
            $claims = $this->validator->validateToken($token);
        } catch (AuthClientError $e) {
            // Do not leak validator internals (expected issuer/audience, etc.) to the client
            $this->reject($event, $e, 'invalid_token', 'Token validation failed');
            return;
        }

        $request->attributes->set(self::CLAIMS_ATTRIBUTE, $claims);
    }

    public static function getClaimsFromRequest(Request $request): ?Claims
    {
        $claims = $request->attributes->get(self::CLAIMS_ATTRIBUTE);
        return $claims instanceof Claims ? $claims : null;
    }

    private function reject(RequestEvent $event, AuthClientError $error, string $errorCode, string $errorDescription): void
    {
        $statusCode = Response::HTTP_UNAUTHORIZED;

        if ($this->errorHandler !== null) {
            $response = ($this->errorHandler)($error, $event->getRequest(), $statusCode, $errorCode, $errorDescription);
            if ($response !== null) {
                $event->setResponse($response);
                return;
            }
        }

        $event->setResponse(ErrorResponder::respond($statusCode, $errorCode, $errorDescription));
    }
}
