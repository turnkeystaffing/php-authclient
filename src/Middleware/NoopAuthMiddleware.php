<?php

declare(strict_types=1);

namespace Turnkey\AuthClient\Middleware;

use Symfony\Component\HttpKernel\Event\RequestEvent;
use Turnkey\AuthClient\Claims;

/**
 * Development middleware that injects preconfigured claims without validation.
 */
class NoopAuthMiddleware
{
    public function __construct(
        private readonly Claims $defaultClaims,
    ) {
    }

    public function onKernelRequest(RequestEvent $event): void
    {
        if (!$event->isMainRequest()) {
            return;
        }

        $event->getRequest()->attributes->set(
            BearerAuthMiddleware::CLAIMS_ATTRIBUTE,
            $this->defaultClaims->deepCopy(),
        );
    }
}
