<?php

declare(strict_types=1);

namespace Turnkey\AuthClient\Middleware;

use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Turnkey\AuthClient\AuthClientError;
use Turnkey\AuthClient\Claims;
use Turnkey\AuthClient\TokenValidatorInterface;

class BearerAuthMiddleware
{
    public const CLAIMS_ATTRIBUTE = 'auth_claims';

    /** @var null|callable(AuthClientError, Request): ?Response */
    private $errorHandler;

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
        $authHeader = $request->headers->get('Authorization', '');

        if (!str_starts_with($authHeader, 'Bearer ')) {
            $this->setErrorResponse($event, $request, AuthClientError::tokenMalformed('missing Bearer token'), 401);
            return;
        }

        $token = substr($authHeader, 7);
        if ($token === '') {
            $this->setErrorResponse($event, $request, AuthClientError::tokenMalformed('empty Bearer token'), 401);
            return;
        }

        try {
            $claims = $this->validator->validateToken($token);
        } catch (AuthClientError $e) {
            $statusCode = $this->httpStatusForError($e);
            $this->setErrorResponse($event, $request, $e, $statusCode);
            return;
        }

        $request->attributes->set(self::CLAIMS_ATTRIBUTE, $claims);
    }

    public static function getClaimsFromRequest(Request $request): ?Claims
    {
        $claims = $request->attributes->get(self::CLAIMS_ATTRIBUTE);
        return $claims instanceof Claims ? $claims : null;
    }

    private function setErrorResponse(RequestEvent $event, Request $request, AuthClientError $error, int $statusCode): void
    {
        if ($this->errorHandler !== null) {
            $response = ($this->errorHandler)($error, $request);
            if ($response !== null) {
                $event->setResponse($response);
                return;
            }
        }

        // RFC 6750 error response
        $wwwAuth = 'Bearer';
        $errorType = match ($error->getErrorType()) {
            AuthClientError::TOKEN_EXPIRED => 'invalid_token',
            AuthClientError::TOKEN_NOT_YET_VALID => 'invalid_token',
            AuthClientError::TOKEN_MALFORMED => 'invalid_request',
            AuthClientError::TOKEN_OVERSIZED => 'invalid_request',
            default => 'invalid_token',
        };

        $wwwAuth .= sprintf(' error="%s", error_description="%s"', $errorType, addslashes($error->getMessage()));

        $event->setResponse(new JsonResponse(
            ['error' => $errorType, 'error_description' => $error->getMessage()],
            $statusCode,
            ['WWW-Authenticate' => $wwwAuth],
        ));
    }

    private function httpStatusForError(AuthClientError $error): int
    {
        return match ($error->getErrorType()) {
            AuthClientError::TOKEN_MALFORMED,
            AuthClientError::TOKEN_OVERSIZED => 400,
            default => 401,
        };
    }
}
