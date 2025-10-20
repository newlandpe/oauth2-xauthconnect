# XAuthConnect Provider for The PHP League OAuth 2.0 Client

[![Latest Stable Version](https://img.shields.io/packagist/v/newlandpe/oauth2-xauthconnect.svg?label=Packagist&logo=packagist)](https://packagist.org/packages/newlandpe/oauth2-xauthconnect)
[![Total Downloads](https://img.shields.io/packagist/dt/newlandpe/oauth2-xauthconnect.svg?label=Downloads&logo=packagist)](https://packagist.org/packages/newlandpe/oauth2-xauthconnect)
[![License](https://img.shields.io/packagist/l/newlandpe/oauth2-xauthconnect.svg?label=Licence&logo=open-source-initiative)](https://packagist.org/packages/newlandpe/oauth2-xauthconnect)
[![Tests](https://img.shields.io/github/actions/workflow/status/newlandpe/oauth2-xauthconnect/phpunit.yml?label=Tests&logo=github)](https://github.com/newlandpe/oauth2-xauthconnect/actions/workflows/phpunit.yml)
[![Test Coverage](https://img.shields.io/codecov/c/github/newlandpe/oauth2-xauthconnect?label=Test%20Coverage&logo=codecov)](https://app.codecov.io/gh/newlandpe/oauth2-xauthconnect)

This package provides an OAuth 2.0 client provider for integrating with an XAuthConnect authorization server. It is built to work with the popular [`league/oauth2-client`](https://github.com/thephpleague/oauth2-client) package.

This provider allows you to easily implement the "Login with XAuthConnect" functionality in any PHP application that uses `league/oauth2-client`.

## Features

- Implements the standard **Authorization Code Grant** flow.
- Supports **PKCE** (Proof Key for Code Exchange) for enhanced security.
- Provides helper methods for XAuthConnect-specific features:
  - **Token Introspection** (`introspectToken`)
  - **Token Revocation** (`revokeToken`)
- Fully compliant with the `league/oauth2-client` `AbstractProvider`.
- Exposes user data (`ID`, `Nickname`) through a `ResourceOwner` object.

## Installation

Install the package via Composer:

```bash
composer require newlandpe/oauth2-xauthconnect
```

### Installing from a local path (for development)

If you're developing this library locally or need to use it as a path repository:

1. Place this library in a directory within your project (e.g., `oauth_libs/oauth2-xauthconnect`).
2. Add the following to your main `composer.json` file:

```json
{
    "require": {
        "newlandpe/oauth2-xauthconnect": "@dev"
    },
    "repositories": [
        {
            "type": "path",
            "url": "./path/to/your/oauth2-xauthconnect"
        }
    ],
    "minimum-stability": "dev"
}
```

3. Run `composer update` to install the dependencies.

## Usage

Follow these steps to integrate XAuthConnect into your application:

### 1. Initialization

First, create an instance of the provider. You must provide all required URLs and client credentials.

```php
require_once 'vendor/autoload.php';

$provider = new ChernegaSergiy\XAuthConnect\OAuth2\Client\Provider\XAuthConnect([
    'clientId'                => 'your-client-id',
    'clientSecret'            => 'your-client-secret',
    'redirectUri'             => 'https://your-redirect-uri.com',

    // URLs of your XAuthConnect Server
    'baseAuthorizationUrl'    => 'http://xauth-server.com/xauth/authorize',
    'baseAccessTokenUrl'      => 'http://xauth-server.com/xauth/token',
    'resourceOwnerDetailsUrl' => 'http://xauth-server.com/xauth/user',
    'introspectUrl'           => 'http://xauth-server.com/xauth/introspect',
    'revokeUrl'               => 'http://xauth-server.com/xauth/revoke'
]);
```

### 2. Authorization

Redirect the user to the XAuthConnect server to authorize your application.

```php
// If we don't have an authorization code then get one
if (!isset($_GET['code'])) {

    // Fetch the authorization URL from the provider; this returns the
    // urlAuthorize URL and generates and stores the state value in the session.
    $authorizationUrl = $provider->getAuthorizationUrl();
    $_SESSION['oauth2state'] = $provider->getState();

    header('Location: ' . $authorizationUrl);
    exit;

// Check given state against previously stored one to mitigate CSRF attack
} elseif (empty($_GET['state']) || (isset($_SESSION['oauth2state']) && $_GET['state'] !== $_SESSION['oauth2state'])) {

    if (isset($_SESSION['oauth2state'])) {
        unset($_SESSION['oauth2state']);
    }

    exit('Invalid state');
}
```

### 3. Getting an Access Token

After the user authorizes, they will be redirected back to your `redirectUri` with a `code`. Use this code to get an access token.

```php
try {
    // Try to get an access token using the authorization code grant.
    $accessToken = $provider->getAccessToken('authorization_code', [
        'code' => $_GET['code']
    ]);

    // We have an access token, let's use it!
    echo 'Access Token: ' . $accessToken->getToken() . "<br>";
    echo 'Refresh Token: ' . $accessToken->getRefreshToken() . "<br>";
    echo 'Expired in: ' . $accessToken->getExpires() . "<br>";
    echo 'Already expired? ' . ($accessToken->hasExpired() ? 'Yes' : 'No') . "<br>";

} catch (\League\OAuth2\Client\Provider\Exception\IdentityProviderException $e) {
    // Failed to get the access token or user details.
    exit($e->getMessage());
}
```

### 4. Getting Resource Owner Details

With the access token, you can now fetch the user's profile information.

```php
try {
    // Returns a XAuthConnectUser instance.
    $user = $provider->getResourceOwner($accessToken);

    printf('Hello, %s!', $user->getNickname());
    echo 'Your UUID is: ' . $user->getId();

    // Get all user data as an array.
    var_dump($user->toArray());

} catch (Exception $e) {
    // Failed to get user details
    exit('Oh dear...');
}
```

## Extra Features

This provider includes methods for XAuthConnect-specific endpoints.

### Introspecting a Token

You can check if a token is active and view its metadata.

```php
$introspectionResult = $provider->introspectToken($accessToken->getToken());

if ($introspectionResult['active']) {
    echo "Token is active. \n";
    echo "Expires at: " . date('Y-m-d H:i:s', $introspectionResult['exp']);
} else {
    echo "Token is not active.";
}
```

### Revoking a Token

You can invalidate an access or refresh token on the server.

```php
// Revoke the access token
$provider->revokeToken($accessToken->getToken());

// Revoke the refresh token
$provider->revokeToken($accessToken->getRefreshToken());

echo "Tokens have been revoked.";
```

## Contributing

Contributions are welcome and appreciated! Here's how you can contribute:

1. Fork the project on GitHub.
2. Create your feature branch (`git checkout -b feature/AmazingFeature`).
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`).
4. Push to the branch (`git push origin feature/AmazingFeature`).
5. Open a Pull Request.

Please make sure to update tests as appropriate and adhere to the existing coding style.

## License

This library is licensed under the CSSM Unlimited License v2.0 (CSSM-ULv2). See the [LICENSE](LICENSE) file for details.
