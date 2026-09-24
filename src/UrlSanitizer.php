<?php

declare(strict_types=1);

namespace Turnkey\AuthClient;

/**
 * @internal
 */
final class UrlSanitizer
{
    /**
     * Strip credentials, query parameters and fragment from a URL for safe logging.
     */
    public static function sanitize(string $url): string
    {
        $parts = parse_url($url);
        if ($parts === false) {
            return '<invalid-url>';
        }

        $out = '';
        if (isset($parts['scheme'])) {
            $out .= $parts['scheme'] . ':';
        }
        if (isset($parts['host'])) {
            $out .= '//' . $parts['host'];
            if (isset($parts['port'])) {
                $out .= ':' . $parts['port'];
            }
        }

        return $out . ($parts['path'] ?? '');
    }
}
