<?php

declare(strict_types=1);

namespace Turnkey\AuthClient\Tests;

use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\HttpKernel\HttpKernelInterface;
use Turnkey\AuthClient\AuthClientError;
use Turnkey\AuthClient\Claims;
use Turnkey\AuthClient\Middleware\BearerAuthMiddleware;
use Turnkey\AuthClient\Middleware\NoopAuthMiddleware;
use Turnkey\AuthClient\Middleware\RequireScopeMiddleware;
use Turnkey\AuthClient\NoopValidator;

class MiddlewareTest extends TestCase
{
    private function createEvent(Request $request, bool $isMainRequest = true): RequestEvent
    {
        $kernel = $this->createStub(HttpKernelInterface::class);
        return new RequestEvent(
            $kernel,
            $request,
            $isMainRequest ? HttpKernelInterface::MAIN_REQUEST : HttpKernelInterface::SUB_REQUEST,
        );
    }

    // --- BearerAuthMiddleware ---

    public function testBearerAuthValidToken(): void
    {
        $validator = new NoopValidator(new Claims(clientId: 'test', scopes: ['read']));
        $middleware = new BearerAuthMiddleware($validator);

        $request = Request::create('/', 'GET', [], [], [], ['HTTP_AUTHORIZATION' => 'Bearer some-token']);
        $event = $this->createEvent($request);

        $middleware->onKernelRequest($event);

        $this->assertNull($event->getResponse());
        $claims = BearerAuthMiddleware::getClaimsFromRequest($request);
        $this->assertNotNull($claims);
        $this->assertSame('test', $claims->clientId);
    }

    public function testBearerAuthMissingHeader(): void
    {
        $validator = new NoopValidator(new Claims(clientId: 'test'));
        $middleware = new BearerAuthMiddleware($validator);

        $request = Request::create('/');
        $event = $this->createEvent($request);

        $middleware->onKernelRequest($event);

        $response = $event->getResponse();
        $this->assertNotNull($response);
        $this->assertSame(401, $response->getStatusCode());
        $this->assertTrue($response->headers->has('WWW-Authenticate'));
    }

    public function testBearerAuthEmptyToken(): void
    {
        $validator = new NoopValidator(new Claims(clientId: 'test'));
        $middleware = new BearerAuthMiddleware($validator);

        $request = Request::create('/', 'GET', [], [], [], ['HTTP_AUTHORIZATION' => 'Bearer ']);
        $event = $this->createEvent($request);

        $middleware->onKernelRequest($event);

        $this->assertNotNull($event->getResponse());
        $this->assertSame(401, $event->getResponse()->getStatusCode());
    }

    public function testBearerAuthSkipsSubRequests(): void
    {
        $validator = new NoopValidator(new Claims(clientId: 'test'));
        $middleware = new BearerAuthMiddleware($validator);

        $request = Request::create('/');
        $event = $this->createEvent($request, isMainRequest: false);

        $middleware->onKernelRequest($event);

        $this->assertNull($event->getResponse());
    }

    public function testBearerAuthValidationError(): void
    {
        $validator = new class implements \Turnkey\AuthClient\TokenValidatorInterface {
            public function validateToken(string $token): Claims
            {
                throw AuthClientError::tokenExpired('token expired');
            }
        };

        $middleware = new BearerAuthMiddleware($validator);
        $request = Request::create('/', 'GET', [], [], [], ['HTTP_AUTHORIZATION' => 'Bearer bad-token']);
        $event = $this->createEvent($request);

        $middleware->onKernelRequest($event);

        $this->assertSame(401, $event->getResponse()->getStatusCode());
    }

    public function testBearerAuthCustomErrorHandler(): void
    {
        $validator = new class implements \Turnkey\AuthClient\TokenValidatorInterface {
            public function validateToken(string $token): Claims
            {
                throw AuthClientError::tokenExpired();
            }
        };

        $middleware = new BearerAuthMiddleware(
            $validator,
            errorHandler: fn() => new Response('custom error', 418),
        );

        $request = Request::create('/', 'GET', [], [], [], ['HTTP_AUTHORIZATION' => 'Bearer x']);
        $event = $this->createEvent($request);

        $middleware->onKernelRequest($event);

        $this->assertSame(418, $event->getResponse()->getStatusCode());
        $this->assertSame('custom error', $event->getResponse()->getContent());
    }

    public function testGetClaimsFromRequestNoClaimsReturnsNull(): void
    {
        $request = Request::create('/');
        $this->assertNull(BearerAuthMiddleware::getClaimsFromRequest($request));
    }

    // --- RequireScopeMiddleware ---

    public function testRequireScopeGranted(): void
    {
        $middleware = RequireScopeMiddleware::single('admin');

        $request = Request::create('/');
        $request->attributes->set(BearerAuthMiddleware::CLAIMS_ATTRIBUTE, new Claims(clientId: 'c1', scopes: ['admin', 'read']));
        $event = $this->createEvent($request);

        $middleware->onKernelRequest($event);

        $this->assertNull($event->getResponse());
    }

    public function testRequireScopeDenied(): void
    {
        $middleware = RequireScopeMiddleware::single('admin');

        $request = Request::create('/');
        $request->attributes->set(BearerAuthMiddleware::CLAIMS_ATTRIBUTE, new Claims(clientId: 'c1', scopes: ['read']));
        $event = $this->createEvent($request);

        $middleware->onKernelRequest($event);

        $this->assertSame(403, $event->getResponse()->getStatusCode());
        $this->assertStringContainsString('insufficient_scope', $event->getResponse()->getContent());
    }

    public function testRequireAnyScopeGranted(): void
    {
        $middleware = RequireScopeMiddleware::anyOf(['admin', 'write']);

        $request = Request::create('/');
        $request->attributes->set(BearerAuthMiddleware::CLAIMS_ATTRIBUTE, new Claims(clientId: 'c1', scopes: ['write']));
        $event = $this->createEvent($request);

        $middleware->onKernelRequest($event);

        $this->assertNull($event->getResponse());
    }

    public function testRequireScopeNoClaims(): void
    {
        $middleware = RequireScopeMiddleware::single('admin');

        $request = Request::create('/');
        $event = $this->createEvent($request);

        $middleware->onKernelRequest($event);

        $this->assertSame(401, $event->getResponse()->getStatusCode());
    }

    public function testRequireScopeSkipsSubRequests(): void
    {
        $middleware = RequireScopeMiddleware::single('admin');

        $request = Request::create('/');
        $event = $this->createEvent($request, isMainRequest: false);

        $middleware->onKernelRequest($event);

        $this->assertNull($event->getResponse());
    }

    // --- NoopAuthMiddleware ---

    public function testNoopAuthInjectsClaims(): void
    {
        $claims = new Claims(clientId: 'dev', scopes: ['admin']);
        $middleware = new NoopAuthMiddleware($claims);

        $request = Request::create('/');
        $event = $this->createEvent($request);

        $middleware->onKernelRequest($event);

        $injected = BearerAuthMiddleware::getClaimsFromRequest($request);
        $this->assertNotNull($injected);
        $this->assertSame('dev', $injected->clientId);
        $this->assertNotSame($claims, $injected); // deep copy
    }
}