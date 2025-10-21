<?php

namespace ChernegaSergiy\XAuthConnect\OAuth2\Client\Provider;

use GuzzleHttp\Client as HttpClient;
use League\OAuth2\Client\Provider\AbstractProvider;
use League\OAuth2\Client\Provider\Exception\IdentityProviderException;
use League\OAuth2\Client\Token\AccessToken;
use League\OAuth2\Client\Token\AccessTokenInterface;
use League\OAuth2\Client\Tool\BearerAuthorizationTrait;
use Psr\Http\Message\ResponseInterface;

class XAuthConnect extends AbstractProvider
{
    use BearerAuthorizationTrait;

    public string $baseAuthorizationUrl;
    public string $baseAccessTokenUrl;
    public string $resourceOwnerDetailsUrl;
    public string $introspectUrl;
    public string $revokeUrl;

    public function __construct(array $options = [], array $collaborators = [])
    {
        parent::__construct($options, $collaborators);

        if (!empty($options['issuer'])) {
            $this->discoverEndpoints($options['issuer']);
        }

        $urlOptions = [
            'baseAuthorizationUrl',
            'baseAccessTokenUrl',
            'resourceOwnerDetailsUrl',
            'introspectUrl',
            'revokeUrl',
        ];

        foreach ($urlOptions as $option) {
            if (!empty($options[$option])) {
                $this->{$option} = $options[$option];
            }
        }

        foreach ($urlOptions as $option) {
            if (empty($this->{$option})) {
                throw new \InvalidArgumentException("The '{$option}' option is required or must be discoverable from the 'issuer' URL.");
            }
        }
    }

    protected function discoverEndpoints(string $issuer): void
    {
        $wellKnownUrl = rtrim($issuer, '/') . '/.well-known/openid-configuration';

        try {
            $httpClient = new HttpClient();
            $response = $httpClient->get($wellKnownUrl);
            $data = json_decode((string) $response->getBody(), true);

            if (json_last_error() !== JSON_ERROR_NONE) {
                throw new \RuntimeException('Failed to parse discovery document: ' . json_last_error_msg());
            }

            $this->baseAuthorizationUrl = $data['authorization_endpoint'] ?? null;
            $this->baseAccessTokenUrl = $data['token_endpoint'] ?? null;
            $this->resourceOwnerDetailsUrl = $data['userinfo_endpoint'] ?? null;
            $this->introspectUrl = $data['introspection_endpoint'] ?? null;
            $this->revokeUrl = $data['revocation_endpoint'] ?? null;

        } catch (\Exception $e) {
            throw new \RuntimeException('Failed to discover endpoints: ' . $e->getMessage(), 0, $e);
        }
    }

    public function getBaseAuthorizationUrl(): string
    {
        return $this->baseAuthorizationUrl;
    }

    public function getBaseAccessTokenUrl(array $params): string
    {
        return $this->baseAccessTokenUrl;
    }

    public function getResourceOwnerDetailsUrl(AccessToken $token): string
    {
        return $this->resourceOwnerDetailsUrl;
    }

    protected function getPkceMethod(): string
    {
        return 'S256';
    }

    public function introspectToken(string $token): array
    {
        $params = [
            'token' => $token,
            'client_id' => $this->clientId,
            'client_secret' => $this->clientSecret,
        ];

        $request = $this->createRequest(self::METHOD_POST, $this->introspectUrl, null, [
            'body' => $this->buildQueryString($params)
        ]);

        return $this->getParsedResponse($request);
    }

    public function revokeToken(string $token): void
    {
        $params = [
            'token' => $token,
            'client_id' => $this->clientId,
            'client_secret' => $this->clientSecret,
        ];

        $request = $this->createRequest(self::METHOD_POST, $this->revokeUrl, null, [
            'body' => $this->buildQueryString($params)
        ]);

        $this->getParsedResponse($request);
    }

    protected function getDefaultScopes(): array
    {
        return ['profile:nickname', 'profile:uuid'];
    }

    protected function getScopeSeparator(): string
    {
        return ' ';
    }

    protected function checkResponse(ResponseInterface $response, $data): void
    {
        if (!empty($data['error'])) {
            $code = $response->getStatusCode();
            $error = $data['error_description'] ?? $data['error'];
            throw new IdentityProviderException($error, $code, $data);
        }
    }

    protected function createResourceOwner(array $response, AccessToken $token): XAuthConnectUser
    {
        return new XAuthConnectUser($response);
    }
}
