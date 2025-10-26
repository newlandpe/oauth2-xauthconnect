<?php

namespace ChernegaSergiy\XAuthConnect\OAuth2\Client\Tests\Provider;

use ChernegaSergiy\XAuthConnect\OAuth2\Client\Provider\XAuthConnect;
use Firebase\JWT\JWT;
use GuzzleHttp\Client as HttpClient;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\Psr7\Response;
use League\OAuth2\Client\Provider\Exception\IdentityProviderException;
use League\OAuth2\Client\Token\AccessToken;
use PHPUnit\Framework\TestCase;
use Mockery as m;

class XAuthConnectTest extends TestCase
{
    protected XAuthConnect $provider;

    protected function setUp(): void
    {
        $this->provider = new XAuthConnect([
            'clientId'                => 'test_client_123',
            'clientSecret'            => 'test_secret_key',
            'redirectUri'             => 'http://127.0.0.1:8081/client.php',
            'baseAuthorizationUrl'    => 'http://127.0.0.1:8010/xauth/authorize',
            'baseAccessTokenUrl'      => 'http://127.0.0.1:8010/xauth/token',
            'resourceOwnerDetailsUrl' => 'http://127.0.0.1:8010/xauth/user',
            'introspectUrl'           => 'http://127.0.0.1:8010/xauth/introspect',
            'revokeUrl'               => 'http://127.0.0.1:8010/xauth/revoke',
            'jwksUrl'                 => 'http://127.0.0.1:8010/xauth/jwks',
            'issuer'                  => 'http://127.0.0.1:8010',
        ]);
    }

    public function tearDown(): void
    {
        m::close();
        parent::tearDown();
    }

    public function testAuthorizationUrl()
    {
        $url = $this->provider->getAuthorizationUrl();
        $uri = parse_url($url);
        parse_str($uri['query'], $query);

        $this->assertArrayHasKey('client_id', $query);
        $this->assertArrayHasKey('redirect_uri', $query);
        $this->assertArrayHasKey('state', $query);
        $this->assertArrayHasKey('scope', $query);
        $this->assertArrayHasKey('response_type', $query);
        $this->assertNotNull($this->provider->getState());
    }

    public function testGetBaseAccessTokenUrl()
    {
        $url = $this->provider->getBaseAccessTokenUrl([]);
        $this->assertEquals('http://127.0.0.1:8010/xauth/token', $url);
    }

    public function testGetResourceOwnerDetailsUrl()
    {
        $token = new AccessToken(['access_token' => 'test_token']);
        $url = $this->provider->getResourceOwnerDetailsUrl($token);
        $this->assertEquals('http://127.0.0.1:8010/xauth/user', $url);
    }

    public function testGetDefaultScopes()
    {
        $reflection = new \ReflectionClass($this->provider);
        $method = $reflection->getMethod('getDefaultScopes');
        $method->setAccessible(true);
        $this->assertEquals(['openid', 'profile:nickname', 'profile:uuid'], $method->invoke($this->provider));
    }

    public function testCheckResponseThrowsException()
    {
        $this->expectException(IdentityProviderException::class);

        $mock = new MockHandler([
            new Response(401, [], json_encode(['error' => 'invalid_client', 'error_description' => 'Client authentication failed']))
        ]);

        $client = new HttpClient(['handler' => $mock]);
        $this->provider->setHttpClient($client);

        $this->provider->getAccessToken('authorization_code', ['code' => 'mock_authorization_code']);
    }

    public function testGetResourceOwner()
    {
        $mock = new MockHandler([
            new Response(200, ['Content-Type' => 'application/json'], json_encode([
                'sub' => '12345',
                'nickname' => 'test_user'
            ]))
        ]);

        $client = new HttpClient(['handler' => $mock]);
        $this->provider->setHttpClient($client);

        $token = new AccessToken(['access_token' => 'test_token']);
        $user = $this->provider->getResourceOwner($token);

        $this->assertEquals('12345', $user->getId());
        $this->assertEquals('test_user', $user->getNickname());
        $this->assertEquals([
            'sub' => '12345',
            'nickname' => 'test_user'
        ], $user->toArray());
    }

    public function testDiscoverySuccess()
    {
        $discoveryDoc = [
            'authorization_endpoint' => 'http://discovered.com/auth',
            'token_endpoint' => 'http://discovered.com/token',
            'userinfo_endpoint' => 'http://discovered.com/user',
            'introspection_endpoint' => 'http://discovered.com/introspect',
            'revocation_endpoint' => 'http://discovered.com/revoke',
            'jwks_uri' => 'http://discovered.com/jwks',
        ];

        $mock = new MockHandler([
            new Response(200, ['Content-Type' => 'application/json'], json_encode($discoveryDoc)),
        ]);

        $client = new HttpClient(['handler' => $mock]);

        $provider = new XAuthConnect([
            'issuer'       => 'http://discovered.com',
            'clientId'     => 'test_client_123',
            'clientSecret' => 'test_secret_key',
            'redirectUri'  => 'http://127.0.0.1:8081/client.php',
        ], ['httpClient' => $client]);

        $this->assertEquals('http://discovered.com/auth', $provider->getBaseAuthorizationUrl([]));
        $this->assertEquals('http://discovered.com/token', $provider->getBaseAccessTokenUrl([]));
        $this->assertEquals('http://discovered.com/user', $provider->getResourceOwnerDetailsUrl(new AccessToken(['access_token' => 'test'])));
    }

    /**
     * @dataProvider idTokenValidationProvider
     */
    public function testIdTokenValidation(array $payload, ?string $nonce, ?string $exception, ?string $exceptionMessage)
    {
        if ($exception) {
            $this->expectException($exception);
            $this->expectExceptionMessage($exceptionMessage);
        }

        $privateKey = openssl_pkey_new([
            'private_key_bits' => 2048,
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
        ]);
        $publicKeyDetails = openssl_pkey_get_details($privateKey);

        $kid = 'test-key-id';
        $idToken = JWT::encode($payload, $privateKey, 'RS256', $kid);

        $jwks = [
            'keys' => [
                [
                    'kty' => 'RSA',
                    'alg' => 'RS256',
                    'kid' => $kid,
                    'n' => rtrim(strtr(base64_encode($publicKeyDetails['rsa']['n']), '+/', '-_'), '='),
                    'e' => rtrim(strtr(base64_encode($publicKeyDetails['rsa']['e']), '+/', '-_'), '='),
                ]
            ]
        ];

        $mock = new MockHandler([
            new Response(200, ['Content-Type' => 'application/json'], json_encode(['access_token' => 'mock_access_token', 'id_token' => $idToken])),
            new Response(200, ['Content-Type' => 'application/json'], json_encode($jwks)),
        ]);

        $client = new HttpClient(['handler' => $mock]);
        $this->provider->setHttpClient($client);

        if ($nonce) {
            $_SESSION['oauth2nonce'] = $nonce;
        }

        $token = $this->provider->getAccessToken('authorization_code', ['code' => 'mock_code']);

        $this->assertNotNull($token->getValues()['id_token_claims']);
    }

    public function idTokenValidationProvider(): array
    {
        $basePayload = [
            'iss' => 'http://127.0.0.1:8010',
            'aud' => 'test_client_123',
            'exp' => time() + 3600,
            'iat' => time(),
            'sub' => 'test-sub',
            'nonce' => 'test-nonce'
        ];

        return [
            'valid token' => [$basePayload, 'test-nonce', null, null],
            'invalid issuer' => [array_merge($basePayload, ['iss' => 'http://invalid-issuer']), 'test-nonce', IdentityProviderException::class, 'Invalid issuer claim'],
            'invalid audience' => [array_merge($basePayload, ['aud' => 'invalid-aud']), 'test-nonce', IdentityProviderException::class, 'Invalid audience claim'],
            'missing nonce in token' => [array_merge($basePayload, ['nonce' => null]), 'test-nonce', IdentityProviderException::class, 'ID token is missing nonce claim'],
            'invalid nonce' => [array_merge($basePayload, ['nonce' => 'invalid-nonce']), 'test-nonce', IdentityProviderException::class, 'Invalid nonce'],
        ];
    }
}