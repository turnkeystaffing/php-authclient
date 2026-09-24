<?php

declare(strict_types=1);

namespace Turnkey\AuthClient\Middleware;

use Symfony\Component\HttpFoundation\JsonResponse;

/**
 * Builds RFC 6750 JSON error responses shared by the auth middleware.
 *
 * @internal
 */
final class ErrorResponder
{
    /**
     * For 401 and 403 responses, sets WWW-Authenticate per RFC 6750 Section 3.
     */
    public static function respond(int $statusCode, string $errorCode, string $errorDescription): JsonResponse
    {
        $headers = [];
        if ($statusCode === 401 || $statusCode === 403) {
            $headers['WWW-Authenticate'] = sprintf(
                'Bearer realm="api", error="%s", error_description="%s"',
                self::escapeQuotedString($errorCode),
                self::escapeQuotedString($errorDescription),
            );
        }

        return new JsonResponse(
            ['error' => $errorCode, 'error_description' => $errorDescription],
            $statusCode,
            $headers,
        );
    }

    /**
     * Escape a value for use inside an RFC 7230 quoted-string; control characters are dropped.
     */
    public static function escapeQuotedString(string $value): string
    {
        $value = preg_replace('/[\x00-\x1F\x7F]/', '', $value) ?? '';

        return addcslashes($value, '\\"');
    }
}
