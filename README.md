# AuthClient PHP

OAuth 2.0 authentication client library for PHP 8.2+ / Symfony 7. Port of [go-authclient](../go/src/go-authclient).

Provides token validation (JWKS + RFC 7662 introspection), token acquisition (client_credentials grant), and Symfony HTTP kernel middleware.

## Installation

```bash
composer require turnkey/authclient
```

For Redis caching, also install Predis:

```bash
composer require predis/predis
```

## Components

| Component | Purpose |
|---|---|
| `JwksValidator` | Local JWT validation using JWKS keys (RSA only) |
| `IntrospectionClient` | Remote token validation via RFC 7662 |
| `OAuthTokenProvider` | Obtain tokens via client_credentials grant |
| `NoopValidator` | Development/testing — returns fixed claims |
| `BearerAuthMiddleware` | Symfony kernel listener for token validation |
| `RequireScopeMiddleware` | Symfony kernel listener for scope enforcement |
| `PrefixedClient` | Redis client wrapper with automatic key prefixing |

## Token Validation with JWKS

Validates JWTs locally using keys fetched from a JWKS endpoint. Enforces RSA-only algorithms (RS256, RS384, RS512) and a 4096-byte token size limit.

```php
use Turnkey\AuthClient\JwksProvider;
use Turnkey\AuthClient\JwksValidator;
use Symfony\Component\HttpClient\HttpClient;

$httpClient = HttpClient::create();
$logger = /* your PSR-3 logger */;

$jwksProvider = new JwksProvider(
    jwksEndpoint: 'https://auth.example.com/.well-known/jwks.json',
    httpClient: $httpClient,
    logger: $logger,
    refreshIntervalSeconds: 300,  // default: 5 minutes
);

$validator = new JwksValidator(
    jwksProvider: $jwksProvider,
    issuer: 'https://auth.example.com',
    audience: 'https://api.example.com',  // required — tokens without this audience are rejected
    logger: $logger,
);

$claims = $validator->validateToken($bearerToken);
echo $claims->clientId;
echo $claims->grantType;   // e.g. "client_credentials"
echo $claims->authTime;    // unix timestamp of user authentication
echo $claims->email;       // WARNING: not sanitized
echo $claims->username;    // WARNING: not sanitized
```

## Token Validation with Introspection

Validates tokens remotely via RFC 7662 introspection endpoint. Supports caching and JWKS fallback on network errors.

```php
use Turnkey\AuthClient\IntrospectionClient;

$client = new IntrospectionClient(
    introspectionEndpoint: 'https://auth.example.com/oauth/introspect',
    clientId: 'my-service',
    clientSecret: 'secret',
    httpClient: $httpClient,
    logger: $logger,
    cache: $cache,              // optional: IntrospectionCacheInterface
    cacheTtlSeconds: 300,       // default: 5 minutes
    fallbackValidator: $jwksValidator,  // optional: fall back on network errors
);

// As validator (returns Claims)
$claims = $client->validateToken($token);

// As introspector (returns IntrospectionResponse)
$response = $client->introspect($token);
if ($response->active) {
    $claims = $response->toClaims();
}
```

## Token Acquisition (Client Credentials)

Obtains bearer tokens for outbound API calls. Caches tokens in memory and proactively refreshes at 80% of lifetime.

```php
use Turnkey\AuthClient\OAuthTokenProvider;

$provider = new OAuthTokenProvider(
    tokenEndpoint: 'https://auth.example.com/oauth/token',
    clientId: 'my-service',
    clientSecret: 'secret',
    httpClient: $httpClient,
    logger: $logger,
    scopes: ['api.read', 'api.write'],
);

$token = $provider->getToken();
// Use $token in Authorization: Bearer header

// Clean up when done
$provider->close();
```

### With Redis Cache (php-fpm)

In php-fpm each request is a fresh process, so the in-memory token cache is lost between requests. Pass a `RedisClientInterface` to persist the token in Redis:

```php
use Turnkey\AuthClient\Redis\PrefixedClient;

$redis = new PrefixedClient(new Predis('tcp://redis:6379'), prefix: 'myapp:');

$provider = new OAuthTokenProvider(
    tokenEndpoint: 'https://auth.example.com/oauth/token',
    clientId: 'my-service',
    clientSecret: 'secret',
    httpClient: $httpClient,
    logger: $logger,
    scopes: ['api.read', 'api.write'],
    redis: $redis,                          // persists token across requests
    cacheKeyNamespace: 'token_provider:',   // default, keys: "myapp:token_provider:oauth_token"
);
```

## Scope Checking

```php
use Turnkey\AuthClient\ScopeChecker;

ScopeChecker::hasScope($claims, 'admin');           // exact match
ScopeChecker::hasAnyScope($claims, ['read', 'write']); // any match
```

## Step-up Authentication

Use `authenticatedWithin()` to enforce that the user recently proved their identity — distinct from token expiry. Useful for sensitive operations like account deletion or permission changes.

```php
// Check if user authenticated within the last 15 minutes (default)
if (!$claims->authenticatedWithin()) {
    // Prompt for re-authentication
}

// Custom window: 5 minutes
if (!$claims->authenticatedWithin(300)) {
    // Prompt for re-authentication
}
```

Returns `false` if `auth_time` is absent from the token (e.g. client_credentials tokens).

In a controller:

```php
class AccountController
{
    public function deleteAccount(Request $request): Response
    {
        $claims = BearerAuthMiddleware::getClaimsFromRequest($request);

        if (!$claims->authenticatedWithin(300)) {
            return new JsonResponse(
                ['error' => 'Step-up authentication required. Please re-authenticate.'],
                Response::HTTP_FORBIDDEN,
            );
        }

        // Proceed with account deletion
    }
}
```

## Symfony Middleware

Register as kernel event listeners (priority ensures auth runs before scope checks).

### Bearer Token Authentication

```php
// services.yaml
services:
    Turnkey\AuthClient\Middleware\BearerAuthMiddleware:
        arguments:
            $validator: '@Turnkey\AuthClient\JwksValidator'
        tags:
            - { name: kernel.event_listener, event: kernel.request, priority: 256 }
```

### Scope Enforcement

```php
// services.yaml
services:
    app.require_admin_scope:
        class: Turnkey\AuthClient\Middleware\RequireScopeMiddleware
        factory: ['Turnkey\AuthClient\Middleware\RequireScopeMiddleware', 'single']
        arguments: ['admin']
        tags:
            - { name: kernel.event_listener, event: kernel.request, priority: 128 }

    # Or require any of multiple scopes
    app.require_write_scope:
        class: Turnkey\AuthClient\Middleware\RequireScopeMiddleware
        factory: ['Turnkey\AuthClient\Middleware\RequireScopeMiddleware', 'anyOf']
        arguments:
            - ['write', 'admin']
        tags:
            - { name: kernel.event_listener, event: kernel.request, priority: 128 }
```

### Accessing Claims in Controllers

```php
use Turnkey\AuthClient\Middleware\BearerAuthMiddleware;

class MyController
{
    public function index(Request $request): Response
    {
        $claims = BearerAuthMiddleware::getClaimsFromRequest($request);

        return new JsonResponse([
            'client_id' => $claims->clientId,
            'scopes' => $claims->scopes,
            'user_id' => $claims->userId,
        ]);
    }
}
```

### Development Mode (NoopAuth)

Bypasses token validation and injects fixed claims. **Never use in production.**

```php
use Turnkey\AuthClient\Claims;
use Turnkey\AuthClient\Middleware\NoopAuthMiddleware;

// services.yaml (dev only)
services:
    Turnkey\AuthClient\Middleware\NoopAuthMiddleware:
        arguments:
            $defaultClaims: !service
                class: Turnkey\AuthClient\Claims
                arguments:
                    $clientId: 'dev-client'
                    $scopes: ['admin', 'read', 'write']
                    $userId: 'dev-user'
                    $email: 'dev@example.com'
        tags:
            - { name: kernel.event_listener, event: kernel.request, priority: 256 }
```

### Custom Error Handling

```php
$middleware = new BearerAuthMiddleware(
    validator: $validator,
    errorHandler: function (AuthClientError $error, Request $request): ?Response {
        // Return a Response to override default, or null to use default
        return new JsonResponse(['msg' => 'auth failed'], 401);
    },
);
```

## Redis Caching with Prefixed Client

The `PrefixedClient` wraps any Redis client (Predis or phpredis) and automatically prefixes all keys — matching the go-redis `PrefixedClient` pattern.

### Basic Usage

```php
use Predis\Client as Predis;
use Turnkey\AuthClient\Redis\PrefixedClient;
use Turnkey\AuthClient\Cache\RedisCache;

$predis = new Predis('tcp://127.0.0.1:6379');

// Wrap with prefix — all keys become "myapp:*"
$redis = new PrefixedClient($predis, prefix: 'myapp:');

// Use with introspection cache
// Keys become: "myapp:introspection:<sha256>"
$cache = new RedisCache($redis);
```

### Default Prefix

If no prefix is specified (or empty string), defaults to `"authclient:"`:

```php
$redis = new PrefixedClient($predis);
// Keys: "authclient:introspection:<sha256>"
```

### Test Isolation

Use unique prefixes per test to avoid key collisions (same pattern as Go):

```php
$prefix = 'test:' . bin2hex(random_bytes(4)) . ':';
$redis = new PrefixedClient($predis, prefix: $prefix);
// Keys: "test:a1b2c3d4:introspection:<sha256>"
```

### With phpredis Extension

```php
$phpredis = new \Redis();
$phpredis->connect('127.0.0.1', 6379);

$redis = new PrefixedClient($phpredis, prefix: 'myapp:');
```

### Retrieving the Prefix

```php
$redis = new PrefixedClient($predis, prefix: 'myapp:');
echo $redis->getPrefix(); // "myapp:"

// Build full key when needed (e.g. for monitoring)
$fullKey = $redis->getPrefix() . 'introspection:' . hash('sha256', $token);
```

## In-Memory Cache (Non-Redis)

For single-process or testing scenarios:

```php
use Turnkey\AuthClient\Cache\InMemoryCache;

$cache = new InMemoryCache(maxSize: 1000);
```

## Full Wiring Example

```php
use Predis\Client as Predis;
use Symfony\Component\HttpClient\HttpClient;
use Turnkey\AuthClient\Cache\RedisCache;
use Turnkey\AuthClient\IntrospectionClient;
use Turnkey\AuthClient\JwksProvider;
use Turnkey\AuthClient\JwksValidator;
use Turnkey\AuthClient\OAuthTokenProvider;
use Turnkey\AuthClient\Redis\PrefixedClient;

$httpClient = HttpClient::create();
$logger = /* PSR-3 logger */;

// Redis with prefix
$redis = new PrefixedClient(new Predis('tcp://redis:6379'), prefix: 'myapp:');
$cache = new RedisCache($redis);

// JWKS validator
$jwksProvider = new JwksProvider(
    jwksEndpoint: 'https://auth.example.com/.well-known/jwks.json',
    httpClient: $httpClient,
    logger: $logger,
);

$jwksValidator = new JwksValidator(
    jwksProvider: $jwksProvider,
    issuer: 'https://auth.example.com',
    audience: 'https://api.example.com',
    logger: $logger,
);

// Introspection with Redis cache + JWKS fallback
$introspectionClient = new IntrospectionClient(
    introspectionEndpoint: 'https://auth.example.com/oauth/introspect',
    clientId: 'my-service',
    clientSecret: getenv('CLIENT_SECRET'),
    httpClient: $httpClient,
    logger: $logger,
    cache: $cache,
    cacheTtlSeconds: 300,
    fallbackValidator: $jwksValidator,
);

// Token provider for outbound API calls
$tokenProvider = new OAuthTokenProvider(
    tokenEndpoint: 'https://auth.example.com/oauth/token',
    clientId: 'my-service',
    clientSecret: getenv('CLIENT_SECRET'),
    httpClient: $httpClient,
    logger: $logger,
    scopes: ['api.read'],
);
```

## Error Handling

All errors throw `AuthClientError` with a typed `getErrorType()` for classification:

```php
use Turnkey\AuthClient\AuthClientError;

try {
    $claims = $validator->validateToken($token);
} catch (AuthClientError $e) {
    match ($e->getErrorType()) {
        AuthClientError::TOKEN_EXPIRED => /* handle expired */,
        AuthClientError::TOKEN_OVERSIZED => /* handle too large */,
        AuthClientError::ALGORITHM_NOT_ALLOWED => /* handle bad algo */,
        AuthClientError::MISSING_CLIENT_ID => /* handle missing claim */,
        AuthClientError::INTROSPECTION_FAILED => /* handle network error */,
        default => /* handle other */,
    };
}
```

## Security Notes

- **Audience validation**: Required and enforced — tokens for other services are rejected
- **RSA only**: HMAC and `none` algorithms are rejected
- **Token size limit**: 4096 bytes max (DoS prevention)
- **No redirects**: HTTP requests disallow redirects to prevent credential leakage
- **HTTPS warnings**: Non-HTTPS endpoints log a warning
- **Unsanitized claims**: `Claims::$email` and `Claims::$username` are NOT sanitized — you must sanitize before using in SQL, HTML, or logs
- **Bounded responses**: HTTP response bodies capped at 1 MB
- **RFC 6749 encoding**: Client credentials are percent-encoded per Section 2.3.1
- **RFC 6750 errors**: Middleware returns proper `WWW-Authenticate` headers

## Ported From

This library is a PHP 8.2 / Symfony 7 port of [go-authclient](../go/src/go-authclient). Components not ported:

- **Gin / FastHTTP middleware** — PHP uses Symfony kernel event listeners instead
- **OpenTelemetry instrumentation** — can be added as a decorator
- **DevServer** — mock OAuth2 server (can be ported separately)
- **Goroutine-based background refresh** — PHP handles this with lazy refresh on access
