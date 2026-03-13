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
| `CacheInterface` | Generic cache interface shared by introspection and token provider |

## Symfony Integration (Full Example)

### 1. Environment Variables

```dotenv
# .env.local
AUTH_ISSUER=https://auth.example.com
AUTH_AUDIENCE=https://api.example.com
AUTH_JWKS_ENDPOINT=https://auth.example.com/.well-known/jwks.json
AUTH_INTROSPECTION_ENDPOINT=https://auth.example.com/oauth/introspect
AUTH_TOKEN_ENDPOINT=https://auth.example.com/oauth/token
AUTH_CLIENT_ID=my-service
AUTH_CLIENT_SECRET=secret
REDIS_URL=tcp://127.0.0.1:6379
```

### 2. HTTP Client Configuration

Configure a scoped HTTP client for auth endpoints in `config/packages/framework.yaml`:

```yaml
# config/packages/framework.yaml
framework:
    http_client:
        scoped_clients:
            authclient.http_client:
                # Timeout and redirect settings matching library security defaults
                timeout: 10
                max_redirects: 0
                headers:
                    Accept: 'application/json'
                # Optional retry on transient failures
                retry_failed:
                    max_retries: 2
                    delay: 500
                    multiplier: 2
                    max_delay: 5000
```

This creates an autowireable service named `authclient.http_client` with:
- **10 second timeout** — matches the library default
- **No redirects** — prevents credential leakage (library enforces this per-request too)
- **Retry with backoff** — 2 retries, 500ms initial delay, doubles each time

### 3. Service Definitions

```yaml
# config/services.yaml
parameters:
    auth.issuer: '%env(AUTH_ISSUER)%'
    auth.audience: '%env(AUTH_AUDIENCE)%'
    auth.jwks_endpoint: '%env(AUTH_JWKS_ENDPOINT)%'
    auth.introspection_endpoint: '%env(AUTH_INTROSPECTION_ENDPOINT)%'
    auth.token_endpoint: '%env(AUTH_TOKEN_ENDPOINT)%'
    auth.client_id: '%env(AUTH_CLIENT_ID)%'
    auth.client_secret: '%env(AUTH_CLIENT_SECRET)%'

services:
    _defaults:
        autowire: true
        autoconfigure: true

    # --- Redis ---

    Predis\Client:
        arguments: ['%env(REDIS_URL)%']

    Turnkey\AuthClient\Redis\PrefixedClient:
        arguments:
            $client: '@Predis\Client'
            $prefix: 'myapp:'

    # --- Cache (shared by introspection + token provider) ---

    Turnkey\AuthClient\CacheInterface:
        class: Turnkey\AuthClient\Cache\RedisCache
        arguments:
            $redis: '@Turnkey\AuthClient\Redis\PrefixedClient'

    # --- JWKS Validator ---

    Turnkey\AuthClient\JwksProvider:
        arguments:
            $jwksEndpoint: '%auth.jwks_endpoint%'
            $httpClient: '@authclient.http_client'

    Turnkey\AuthClient\JwksValidator:
        arguments:
            $jwksProvider: '@Turnkey\AuthClient\JwksProvider'
            $issuer: '%auth.issuer%'
            $audience: '%auth.audience%'

    # --- Introspection Client ---

    Turnkey\AuthClient\IntrospectionClient:
        arguments:
            $introspectionEndpoint: '%auth.introspection_endpoint%'
            $clientId: '%auth.client_id%'
            $clientSecret: '%auth.client_secret%'
            $httpClient: '@authclient.http_client'
            $cache: '@Turnkey\AuthClient\CacheInterface'
            $cacheTtlSeconds: 300
            $fallbackValidator: '@Turnkey\AuthClient\JwksValidator'

    # --- Token Provider (outbound API calls) ---

    Turnkey\AuthClient\OAuthTokenProvider:
        arguments:
            $tokenEndpoint: '%auth.token_endpoint%'
            $clientId: '%auth.client_id%'
            $clientSecret: '%auth.client_secret%'
            $httpClient: '@authclient.http_client'
            $scopes: ['api.read']
            $cache: '@Turnkey\AuthClient\CacheInterface'
            $cacheKeyNamespace: 'token_provider:'

    # --- Bind validator interface to JWKS (or IntrospectionClient) ---

    Turnkey\AuthClient\TokenValidatorInterface: '@Turnkey\AuthClient\JwksValidator'

    # --- Middleware ---

    Turnkey\AuthClient\Middleware\BearerAuthMiddleware:
        arguments:
            $validator: '@Turnkey\AuthClient\TokenValidatorInterface'
        tags:
            - { name: kernel.event_listener, event: kernel.request, priority: 256 }

    app.require_admin_scope:
        class: Turnkey\AuthClient\Middleware\RequireScopeMiddleware
        factory: ['Turnkey\AuthClient\Middleware\RequireScopeMiddleware', 'single']
        arguments: ['admin']
        tags:
            - { name: kernel.event_listener, event: kernel.request, priority: 128 }
```

### 4. Development Override

```yaml
# config/services_dev.yaml
services:
    # Replace real auth with noop in dev
    Turnkey\AuthClient\Middleware\BearerAuthMiddleware:
        class: Turnkey\AuthClient\Middleware\NoopAuthMiddleware
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

### 5. Using in Controllers

```php
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Turnkey\AuthClient\Middleware\BearerAuthMiddleware;
use Turnkey\AuthClient\OAuthTokenProvider;

class MyController
{
    public function __construct(
        private readonly OAuthTokenProvider $tokenProvider,
    ) {
    }

    // Read claims set by BearerAuthMiddleware
    public function profile(Request $request): Response
    {
        $claims = BearerAuthMiddleware::getClaimsFromRequest($request);

        return new JsonResponse([
            'client_id' => $claims->clientId,
            'scopes' => $claims->scopes,
            'user_id' => $claims->userId,
        ]);
    }

    // Use token provider for outbound API calls
    public function callExternalApi(): Response
    {
        $token = $this->tokenProvider->getToken();

        // Use $token in Authorization: Bearer header for outbound requests
        // ...
    }
}
```

---

## Standalone Usage (Without Symfony DI)

### HTTP Client Configuration

```php
use Symfony\Component\HttpClient\HttpClient;
use Symfony\Component\HttpClient\RetryableHttpClient;

// Basic client
$httpClient = HttpClient::create([
    'timeout' => 10,
    'max_redirects' => 0,
]);

// With retry (optional)
$httpClient = new RetryableHttpClient(
    HttpClient::create([
        'timeout' => 10,
        'max_redirects' => 0,
    ]),
    maxRetries: 2,
);
```

### Token Validation with JWKS

```php
use Turnkey\AuthClient\JwksProvider;
use Turnkey\AuthClient\JwksValidator;

$jwksProvider = new JwksProvider(
    jwksEndpoint: 'https://auth.example.com/.well-known/jwks.json',
    httpClient: $httpClient,
    logger: $logger,
    refreshIntervalSeconds: 300,  // default: 5 minutes
);

$validator = new JwksValidator(
    jwksProvider: $jwksProvider,
    issuer: 'https://auth.example.com',
    audience: 'https://api.example.com',  // required
    logger: $logger,
);

$claims = $validator->validateToken($bearerToken);
echo $claims->clientId;
echo $claims->grantType;   // e.g. "client_credentials"
echo $claims->authTime;    // unix timestamp of user authentication
echo $claims->email;       // WARNING: not sanitized
echo $claims->username;    // WARNING: not sanitized
```

### Token Validation with Introspection

```php
use Turnkey\AuthClient\IntrospectionClient;

$client = new IntrospectionClient(
    introspectionEndpoint: 'https://auth.example.com/oauth/introspect',
    clientId: 'my-service',
    clientSecret: 'secret',
    httpClient: $httpClient,
    logger: $logger,
    cache: $cache,              // optional: CacheInterface
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

### Token Acquisition (Client Credentials)

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

#### With Persistent Cache (php-fpm)

In php-fpm each request is a fresh process, so the in-memory token cache is lost. Pass a `CacheInterface` to persist across requests:

```php
$provider = new OAuthTokenProvider(
    tokenEndpoint: 'https://auth.example.com/oauth/token',
    clientId: 'my-service',
    clientSecret: 'secret',
    httpClient: $httpClient,
    logger: $logger,
    scopes: ['api.read', 'api.write'],
    cache: $cache,                          // persists token across requests
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

## Caching

Both `IntrospectionClient` and `OAuthTokenProvider` share the same `CacheInterface`.

### Redis Cache with Prefixed Client

```php
use Predis\Client as Predis;
use Turnkey\AuthClient\Redis\PrefixedClient;
use Turnkey\AuthClient\Cache\RedisCache;

$predis = new Predis('tcp://127.0.0.1:6379');
$redis = new PrefixedClient($predis, prefix: 'myapp:');

// Introspection cache with namespace: keys → "myapp:introspection:<sha256>"
$introspectionCache = new RedisCache($redis, keyNamespace: 'introspection:');

// Token provider cache with namespace: keys → "myapp:token_provider:oauth_token"
// (namespace configured via OAuthTokenProvider's $cacheKeyNamespace)
$tokenCache = new RedisCache($redis);
```

### Default Prefix

If no prefix is specified (or empty string), defaults to `"authclient:"`:

```php
$redis = new PrefixedClient($predis);
```

### With phpredis Extension

```php
$phpredis = new \Redis();
$phpredis->connect('127.0.0.1', 6379);

$redis = new PrefixedClient($phpredis, prefix: 'myapp:');
```

### In-Memory Cache

For single-process or testing scenarios:

```php
use Turnkey\AuthClient\Cache\InMemoryCache;

$cache = new InMemoryCache(maxSize: 1000);
```

### Test Isolation

Use unique prefixes per test to avoid key collisions:

```php
$prefix = 'test:' . bin2hex(random_bytes(4)) . ':';
$redis = new PrefixedClient($predis, prefix: $prefix);
```

## Middleware

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

### Scope Enforcement (Multiple Scopes)

```yaml
# Any of these scopes grants access (OR logic)
app.require_write_scope:
    class: Turnkey\AuthClient\Middleware\RequireScopeMiddleware
    factory: ['Turnkey\AuthClient\Middleware\RequireScopeMiddleware', 'anyOf']
    arguments:
        - ['write', 'admin']
    tags:
        - { name: kernel.event_listener, event: kernel.request, priority: 128 }
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