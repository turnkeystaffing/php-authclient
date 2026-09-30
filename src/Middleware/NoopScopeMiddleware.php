<?php

declare(strict_types=1);

namespace Turnkey\AuthClient\Middleware;

use Symfony\Component\HttpKernel\Event\RequestEvent;

/**
 * Development scope middleware that always passes through. Pair with NoopAuthMiddleware.
 */
class NoopScopeMiddleware
{
    public function onKernelRequest(RequestEvent $event): void
    {
    }
}
