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
use Turnkey\AuthClient\Middleware\NoopScopeMiddleware;
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
        $validator = new NoopValidator(new Claims(clientId: 'test', scopes: ['svc:data:read']));
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
        $middleware = RequireScopeMiddleware::single('svc:admin:all');

        $request = Request::create('/');
        $request->attributes->set(BearerAuthMiddleware::CLAIMS_ATTRIBUTE, new Claims(clientId: 'c1', scopes: ['svc:admin:all', 'svc:data:read']));
        $event = $this->createEvent($request);

        $middleware->onKernelRequest($event);

        $this->assertNull($event->getResponse());
    }

    public function testRequireScopeDenied(): void
    {
        $middleware = RequireScopeMiddleware::single('svc:admin:all');

        $request = Request::create('/');
        $request->attributes->set(BearerAuthMiddleware::CLAIMS_ATTRIBUTE, new Claims(clientId: 'c1', scopes: ['svc:data:read']));
        $event = $this->createEvent($request);

        $middleware->onKernelRequest($event);

        $this->assertSame(403, $event->getResponse()->getStatusCode());
        $this->assertStringContainsString('insufficient_scope', $event->getResponse()->getContent());
    }

    public function testRequireAnyScopeGranted(): void
    {
        $middleware = RequireScopeMiddleware::anyOf(['svc:admin:all', 'svc:data:write']);

        $request = Request::create('/');
        $request->attributes->set(BearerAuthMiddleware::CLAIMS_ATTRIBUTE, new Claims(clientId: 'c1', scopes: ['svc:data:write']));
        $event = $this->createEvent($request);

        $middleware->onKernelRequest($event);

        $this->assertNull($event->getResponse());
    }

    public function testRequireScopeNoClaims(): void
    {
        $middleware = RequireScopeMiddleware::single('svc:admin:all');

        $request = Request::create('/');
        $event = $this->createEvent($request);

        $middleware->onKernelRequest($event);

        $this->assertSame(401, $event->getResponse()->getStatusCode());
    }

    public function testRequireScopeSkipsSubRequests(): void
    {
        $middleware = RequireScopeMiddleware::single('svc:admin:all');

        $request = Request::create('/');
        $event = $this->createEvent($request, isMainRequest: false);

        $middleware->onKernelRequest($event);

        $this->assertNull($event->getResponse());
    }

    // --- NoopAuthMiddleware ---

    public function testNoopAuthInjectsClaims(): void
    {
        $claims = new Claims(clientId: 'dev', scopes: ['svc:admin:all']);
        $middleware = new NoopAuthMiddleware($claims);

        $request = Request::create('/');
        $event = $this->createEvent($request);

        $middleware->onKernelRequest($event);

        $injected = BearerAuthMiddleware::getClaimsFromRequest($request);
        $this->assertNotNull($injected);
        $this->assertSame('dev', $injected->clientId);
        $this->assertNotSame($claims, $injected); // deep copy
    }

    // --- go-authclient parity: BearerAuthMiddleware ---

    private function bearer(string $header, ?\Turnkey\AuthClient\TokenValidatorInterface $validator = null): ?Response
    {
        $middleware = new BearerAuthMiddleware($validator ?? new NoopValidator(new Claims(clientId: 'test')));
        $server = $header === '' ? [] : ['HTTP_AUTHORIZATION' => $header];
        $event = $this->createEvent(Request::create('/', 'GET', [], [], [], $server));
        $middleware->onKernelRequest($event);

        return $event->getResponse();
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('malformedHeaderProvider')]
    public function testBearerAuthMalformedHeaders(string $header, string $description): void
    {
        $response = $this->bearer($header);
        $this->assertNotNull($response);
        $this->assertSame(401, $response->getStatusCode());
        $body = json_decode((string) $response->getContent(), true);
        $this->assertSame(['error' => 'invalid_request', 'error_description' => $description], $body);
        $this->assertSame(
            sprintf('Bearer realm="api", error="invalid_request", error_description="%s"', $description),
            $response->headers->get('WWW-Authenticate'),
        );
    }

    public static function malformedHeaderProvider(): iterable
    {
        yield 'missing' => ['', 'Missing authorization header'];
        yield 'basic scheme' => ['Basic abc', 'Invalid authorization header format'];
        yield 'too short' => ['Bear', 'Invalid authorization header format'];
        yield 'whitespace token' => ['Bearer    ', 'Empty bearer token'];
        yield 'oversized' => ['Bearer ' . str_repeat('a', 4097), 'Bearer token exceeds maximum length'];
    }

    public function testBearerAuthSchemeIsCaseInsensitiveAndTrimmed(): void
    {
        $seen = null;
        $validator = new class($seen) implements \Turnkey\AuthClient\TokenValidatorInterface {
            public function __construct(public ?string &$seen)
            {
            }

            public function validateToken(string $token): Claims
            {
                $this->seen = $token;
                return new Claims(clientId: 'c1');
            }
        };

        $this->assertNull($this->bearer('bEaReR   tok-1  ', $validator));
        $this->assertSame('tok-1', $seen);
    }

    public function testBearerAuthValidationErrorDoesNotLeakDetails(): void
    {
        $validator = new class implements \Turnkey\AuthClient\TokenValidatorInterface {
            public function validateToken(string $token): Claims
            {
                throw AuthClientError::tokenMalformed('invalid issuer: expected "https://secret-issuer"');
            }
        };

        $response = $this->bearer('Bearer x', $validator);
        $this->assertSame(401, $response->getStatusCode());
        $this->assertStringNotContainsString('secret-issuer', (string) $response->getContent());
        $this->assertStringNotContainsString('secret-issuer', (string) $response->headers->get('WWW-Authenticate'));
        $this->assertSame('invalid_token', json_decode((string) $response->getContent(), true)['error']);
    }

    public function testBearerAuthErrorHandlerReceivesStatusAndCodes(): void
    {
        $captured = [];
        $middleware = new BearerAuthMiddleware(
            new NoopValidator(new Claims(clientId: 't')),
            function (AuthClientError $e, Request $r, int $status, string $code, string $desc) use (&$captured) {
                $captured = [$e->getErrorType(), $status, $code, $desc];
                return null; // fall back to default response
            },
        );
        $event = $this->createEvent(Request::create('/'));
        $middleware->onKernelRequest($event);

        $this->assertSame([AuthClientError::TOKEN_MALFORMED, 401, 'invalid_request', 'Missing authorization header'], $captured);
        $this->assertSame(401, $event->getResponse()->getStatusCode());
    }

    // --- go-authclient parity: RequireScopeMiddleware ---

    private function requireScope(RequireScopeMiddleware $middleware, ?Claims $claims): ?Response
    {
        $request = Request::create('/');
        if ($claims !== null) {
            $request->attributes->set(BearerAuthMiddleware::CLAIMS_ATTRIBUTE, $claims);
        }
        $event = $this->createEvent($request);
        $middleware->onKernelRequest($event);

        return $event->getResponse();
    }

    public function testRequireScopeResponseFormat(): void
    {
        $response = $this->requireScope(RequireScopeMiddleware::single('svc:admin:all'), new Claims(clientId: 'c1'));
        $this->assertSame(403, $response->getStatusCode());
        $this->assertSame(
            ['error' => 'insufficient_scope', 'error_description' => 'Required scope: svc:admin:all'],
            json_decode((string) $response->getContent(), true),
        );
        $this->assertSame(
            'Bearer realm="api", error="insufficient_scope", error_description="Required scope: svc:admin:all"',
            $response->headers->get('WWW-Authenticate'),
        );

        $response = $this->requireScope(RequireScopeMiddleware::anyOf(['a:read', 'b:read']), new Claims(clientId: 'c1'));
        $this->assertSame('Required one of scopes: a:read, b:read', json_decode((string) $response->getContent(), true)['error_description']);

        $response = $this->requireScope(RequireScopeMiddleware::single('a:read'), null);
        $this->assertSame(401, $response->getStatusCode());
        $this->assertSame(
            ['error' => 'invalid_token', 'error_description' => 'Missing authentication context'],
            json_decode((string) $response->getContent(), true),
        );
    }

    public function testRequireScopeWildcardVersusExact(): void
    {
        $claims = new Claims(clientId: 'c1', scopes: ['bgc:*']);

        $this->assertNull($this->requireScope(RequireScopeMiddleware::single('bgc:contractors:read'), $claims));
        $this->assertNull($this->requireScope(RequireScopeMiddleware::anyOf(['x:read', 'bgc:contractors:read']), $claims));
        $this->assertSame(403, $this->requireScope(RequireScopeMiddleware::exact('bgc:contractors:read'), $claims)->getStatusCode());
        $this->assertSame(403, $this->requireScope(RequireScopeMiddleware::anyOfExact(['x:read', 'bgc:contractors:read']), $claims)->getStatusCode());
        $this->assertNull($this->requireScope(RequireScopeMiddleware::exact('bgc:*'), $claims));
    }

    public function testRequireScopeEmptyScopesRejected(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        RequireScopeMiddleware::anyOf([]);
    }

    public function testRequireScopeEmptyScopeStringRejected(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        RequireScopeMiddleware::single('');
    }

    public function testRequireScopeCustomErrorHandler(): void
    {
        $middleware = RequireScopeMiddleware::single(
            'a:read',
            fn(Request $r, int $status, string $code, string $desc) => new Response("{$status} {$code}", 418),
        );
        $response = $this->requireScope($middleware, new Claims(clientId: 'c1'));
        $this->assertSame(418, $response->getStatusCode());
        $this->assertSame('403 insufficient_scope', $response->getContent());
    }

    public function testNoopScopeMiddlewarePassesThrough(): void
    {
        $event = $this->createEvent(Request::create('/'));
        (new NoopScopeMiddleware())->onKernelRequest($event);
        $this->assertNull($event->getResponse());
    }

    public function testErrorResponderEscapesQuotedString(): void
    {
        $this->assertSame('a\\\\b\\"c', \Turnkey\AuthClient\Middleware\ErrorResponder::escapeQuotedString("a\\b\"c\n"));
    }
}
