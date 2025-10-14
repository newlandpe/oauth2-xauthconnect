# XAuthConnect Provider for The PHP League OAuth 2.0 Client

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

This provider is intended to be used as a local `path` repository in your project's `composer.json`.

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

## License

This project is licensed under the CSSM Unlimited License v2.0 (CSSM-ULv2). Please note that this is a custom license. See the [LICENSE](LICENSE) file for details.
