<?php

declare(strict_types=1);

namespace Turnkey\AuthClient\Middleware;

use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Turnkey\AuthClient\ScopeChecker;

class RequireScopeMiddleware
{
    /**
     * @param string[] $requiredScopes If multiple, any one suffices (OR logic).
     */
    public function __construct(
        private readonly array $requiredScopes,
    ) {
    }

    /**
     * Create a middleware that requires a single scope.
     */
    public static function single(string $scope): self
    {
        return new self([$scope]);
    }

    /**
     * Create a middleware that requires any one of the given scopes.
     */
    public static function anyOf(array $scopes): self
    {
        return new self($scopes);
    }

    public function onKernelRequest(RequestEvent $event): void
    {
        if (!$event->isMainRequest()) {
            return;
        }

        $request = $event->getRequest();
        $claims = BearerAuthMiddleware::getClaimsFromRequest($request);

        if ($claims === null) {
            $event->setResponse(new JsonResponse(
                ['error' => 'unauthorized', 'error_description' => 'no authentication claims found'],
                Response::HTTP_UNAUTHORIZED,
            ));
            return;
        }

        $hasScope = count($this->requiredScopes) === 1
            ? ScopeChecker::hasScope($claims, $this->requiredScopes[0])
            : ScopeChecker::hasAnyScope($claims, $this->requiredScopes);

        if (!$hasScope) {
            $event->setResponse(new JsonResponse(
                [
                    'error' => 'insufficient_scope',
                    'error_description' => sprintf(
                        'required scope(s): %s',
                        implode(', ', $this->requiredScopes)
                    ),
                ],
                Response::HTTP_FORBIDDEN,
                ['WWW-Authenticate' => sprintf('Bearer error="insufficient_scope", scope="%s"', implode(' ', $this->requiredScopes))],
            ));
        }
    }
}
