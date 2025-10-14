<?php

namespace ChernegaSergiy\XAuthConnect\OAuth2\Client\Tests\Provider;

use ChernegaSergiy\XAuthConnect\OAuth2\Client\Provider\XAuthConnect;
use GuzzleHttp\Client as HttpClient;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\Psr7\Response;
use League\OAuth2\Client\Provider\Exception\IdentityProviderException;
use League\OAuth2\Client\Token\AccessToken;
use PHPUnit\Framework\TestCase;
use Mockery as m;

class XAuthConnectTest extends TestCase
{
    protected $provider;

    protected function setUp(): void
    {
        $this->provider = new XAuthConnect([
            'clientId'     => 'test_client_123',
            'clientSecret' => 'test_secret_key',
            'redirectUri'  => 'http://127.0.0.1:8081/client.php',
            'baseAuthorizationUrl'    => 'http://127.0.0.1:8010/xauth/authorize',
            'baseAccessTokenUrl'      => 'http://127.0.0.1:8010/xauth/token',
            'resourceOwnerDetailsUrl' => 'http://127.0.0.1:8010/xauth/user',
            'introspectUrl'           => 'http://127.0.0.1:8010/xauth/introspect',
            'revokeUrl'               => 'http://127.0.0.1:8010/xauth/revoke',
        ]);
    }

    public function tearDown(): void
    {
        m::close();
        parent::tearDown();
    }

    public function testRequiredOptions()
    {
        $this->expectException(\InvalidArgumentException::class);
        new XAuthConnect([]);
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
        $this->assertEquals(['profile:nickname', 'profile:uuid'], $method->invoke($this->provider));
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
                'profile:uuid' => '12345',
                'profile:nickname' => 'test_user'
            ]))
        ]);

        $client = new HttpClient(['handler' => $mock]);
        $this->provider->setHttpClient($client);

        $token = new AccessToken(['access_token' => 'test_token']);
        $user = $this->provider->getResourceOwner($token);

        $this->assertEquals('12345', $user->getId());
        $this->assertEquals('test_user', $user->getNickname());
        $this->assertEquals([
            'profile:uuid' => '12345',
            'profile:nickname' => 'test_user'
        ], $user->toArray());
    }

    public function testIntrospectToken()
    {
        $mock = new MockHandler([
            new Response(200, ['Content-Type' => 'application/json'], json_encode(['active' => true])),
        ]);

        $client = new HttpClient(['handler' => $mock]);
        $this->provider->setHttpClient($client);

        $result = $this->provider->introspectToken('test_token');

        $this->assertIsArray($result);
        $this->assertTrue($result['active']);
    }

    public function testRevokeToken()
    {
        $mock = new MockHandler([
            new Response(200),
        ]);

        $client = new HttpClient(['handler' => $mock]);
        $this->provider->setHttpClient($client);

        $this->provider->revokeToken('test_token');
        $this->assertTrue(true); // No exception thrown
    }
}
