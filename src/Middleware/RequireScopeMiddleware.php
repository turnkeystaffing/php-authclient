<?php

declare(strict_types=1);

namespace Turnkey\AuthClient\Middleware;

use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Turnkey\AuthClient\ScopeChecker;

/**
 * Enforces scopes on requests authenticated by BearerAuthMiddleware (or NoopAuthMiddleware).
 *
 * Returns 401 if no claims are present and 403 if the required scope(s) are missing.
 */
class RequireScopeMiddleware
{
    /** @var string[] */
    private readonly array $requiredScopes;

    /** @var null|callable(Request, int, string, string): ?Response */
    private $errorHandler;

    /**
     * @param string[] $requiredScopes If multiple, any one suffices (OR logic).
     * @param bool $allowWildcard When true (default), user wildcard scopes such as "bgc:*" satisfy
     *                            "bgc:contractors:read". When false, only exact matches are accepted.
     * @param null|callable(Request $request, int $statusCode, string $errorCode, string $errorDescription): ?Response $errorHandler
     *        Custom error response builder. Returning null falls back to the default RFC 6750 JSON response.
     */
    public function __construct(
        array $requiredScopes,
        private readonly bool $allowWildcard = true,
        ?callable $errorHandler = null,
    ) {
        $requiredScopes = array_values($requiredScopes);
        if ($requiredScopes === []) {
            throw new \InvalidArgumentException('RequireScopeMiddleware: scopes cannot be empty');
        }
        foreach ($requiredScopes as $scope) {
            if ($scope === '') {
                throw new \InvalidArgumentException('RequireScopeMiddleware: scope cannot be empty');
            }
        }

        $this->requiredScopes = $requiredScopes;
        $this->errorHandler = $errorHandler;
    }

    /**
     * Create a middleware that requires a single scope (wildcard-aware).
     */
    public static function single(string $scope, ?callable $errorHandler = null): self
    {
        return new self([$scope], true, $errorHandler);
    }

    /**
     * Create a middleware that requires any one of the given scopes (wildcard-aware).
     *
     * @param string[] $scopes
     */
    public static function anyOf(array $scopes, ?callable $errorHandler = null): self
    {
        return new self($scopes, true, $errorHandler);
    }

    /**
     * Create a middleware that requires a single scope, exact match only
     * (go-authclient HTTPRequireScope semantics).
     */
    public static function exact(string $scope, ?callable $errorHandler = null): self
    {
        return new self([$scope], false, $errorHandler);
    }

    /**
     * Create a middleware that requires any one of the given scopes, exact match only
     * (go-authclient HTTPRequireAnyScope semantics).
     *
     * @param string[] $scopes
     */
    public static function anyOfExact(array $scopes, ?callable $errorHandler = null): self
    {
        return new self($scopes, false, $errorHandler);
    }

    public function onKernelRequest(RequestEvent $event): void
    {
        if (!$event->isMainRequest()) {
            return;
        }

        $request = $event->getRequest();
        $claims = BearerAuthMiddleware::getClaimsFromRequest($request);

        if ($claims === null) {
            $this->reject($event, Response::HTTP_UNAUTHORIZED, 'invalid_token', 'Missing authentication context');
            return;
        }

        $single = count($this->requiredScopes) === 1;
        $hasScope = match (true) {
            $single && $this->allowWildcard => ScopeChecker::hasScope($claims, $this->requiredScopes[0]),
            $single => ScopeChecker::hasScopeExact($claims, $this->requiredScopes[0]),
            $this->allowWildcard => ScopeChecker::hasAnyScope($claims, $this->requiredScopes),
            default => ScopeChecker::hasAnyScopeExact($claims, $this->requiredScopes),
        };

        if (!$hasScope) {
            $description = $single
                ? 'Required scope: ' . $this->requiredScopes[0]
                : 'Required one of scopes: ' . implode(', ', $this->requiredScopes);
            $this->reject($event, Response::HTTP_FORBIDDEN, 'insufficient_scope', $description);
        }
    }

    private function reject(RequestEvent $event, int $statusCode, string $errorCode, string $errorDescription): void
    {
        if ($this->errorHandler !== null) {
            $response = ($this->errorHandler)($event->getRequest(), $statusCode, $errorCode, $errorDescription);
            if ($response !== null) {
                $event->setResponse($response);
                return;
            }
        }

        $event->setResponse(ErrorResponder::respond($statusCode, $errorCode, $errorDescription));
    }
}
