<?php

declare(strict_types=1);

namespace Turnkey\AuthClient\Discovery;

use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * Serves a pre-serialized ScopeManifest as JSON at a discovery endpoint.
 * Designed to sit behind BearerAuthMiddleware and RequireScopeMiddleware for access control.
 *
 * Usable as an invokable Symfony controller. The manifest is serialized once at construction
 * (and on reload()), never per request.
 */
final class DiscoveryHandler
{
    private const METHOD_NOT_ALLOWED_JSON = '{"error":"method_not_allowed","error_description":"Only GET is supported"}';

    private string $json;

    private function __construct(string $json, private readonly ?string $filePath = null)
    {
        $this->json = $json;
    }

    /**
     * Create a handler from an in-memory manifest. The manifest is validated before serialization.
     *
     * @throws ManifestValidationException
     */
    public static function fromManifest(ScopeManifest $manifest): self
    {
        ManifestValidator::validate($manifest);

        return new self($manifest->toJson());
    }

    /**
     * Create a handler by loading a manifest from a YAML or JSON file (see ManifestLoader::fromFile).
     * The path is stored so the manifest can be refreshed with reload().
     *
     * @throws ManifestException
     */
    public static function fromFile(string $path): self
    {
        if ($path === '') {
            throw new \InvalidArgumentException('discovery handler: path cannot be empty');
        }

        try {
            $manifest = ManifestLoader::fromFile($path);
        } catch (ManifestValidationException $e) {
            throw $e;
        } catch (ManifestException $e) {
            throw new ManifestException('discovery handler: ' . $e->getMessage(), 0, $e);
        }

        return new self($manifest->toJson(), $path);
    }

    /**
     * Reload the manifest from the original file, re-validate and replace the served JSON.
     * On failure the previously served manifest is preserved.
     *
     * @throws \LogicException if the handler was not created from a file
     * @throws ManifestException on load/validation failure
     */
    public function reload(): void
    {
        if ($this->filePath === null) {
            throw new \LogicException('discovery handler: reload requires file-based handler');
        }

        $this->json = ManifestLoader::fromFile($this->filePath)->toJson();
    }

    /**
     * GET returns the manifest JSON; any other method returns 405 with "Allow: GET".
     */
    public function __invoke(Request $request): Response
    {
        if ($request->getMethod() !== Request::METHOD_GET) {
            return new Response(self::METHOD_NOT_ALLOWED_JSON, Response::HTTP_METHOD_NOT_ALLOWED, [
                'Allow' => 'GET',
                'Content-Type' => 'application/json',
                'X-Content-Type-Options' => 'nosniff',
            ]);
        }

        return new Response($this->json, Response::HTTP_OK, [
            'Content-Type' => 'application/json',
            'Cache-Control' => 'no-store',
            'X-Content-Type-Options' => 'nosniff',
        ]);
    }

    /**
     * The pre-serialized manifest JSON currently being served.
     */
    public function getJson(): string
    {
        return $this->json;
    }
}
