# OAuth2PKCE client

This library implements the OAuth Authorization Code
grant ([RFC 6749 § 4.1][]) with PKCE ([RFC 7636][]) for single page applications in the browser.

[RFC 6749 § 4.1]: https://tools.ietf.org/html/rfc6749#section-4.1
[RFC 7636]: https://tools.ietf.org/html/rfc7636

## Installation

`npm install oauth2-pkce`

## Usage

### Create Client

First you need to create the client with all the parameters necessary for OAuth. There are also three callbacks available that allow to you react on common events.

```
const oauthClient = new OAuth2AuthCodePkceClient({
    scopes: ['openid', 'blah'],
    authorizationUrl: AUTH_API + 'authorize/',
    tokenUrl: 'https://auth.example.com/token/',
    clientId: 'identifier-for-the-app-which-is-registered-in-the-backend',
    redirectUrl: 'https://app.example.com/return/'`,
    storeRefreshToken: false,
    // optional:
    onAccessTokenExpiry() {
        // when the access token has expired
        return oauthClient.exchangeRefreshTokenForAccessToken();
    },
    onInvalidGrant() {
        // when there is an error getting a token with a grant
        console.warn('Invalid grant! Auth code or refresh token need to be renewed.');
        // you probably want to redirect the user to the login page here
    },
    onInvalidToken() {
        // the token is invalid, e. g. because it has been removed in the backend
        console.warn('Invalid token! Refresh and access tokens need to be renewed.');
        // you probably want to redirect the user to the login page here
    }
});
```

The optional `storeRefreshToken` setting tells the client to store refresh tokens from the auth server in the browser's local storage in order to be logged in indefinitely (until calling `reset()`), defaults to `false`. This is not considered secure, so use cautiously. The refresh token is stored in memory anyway, so the users are logged in as long as they don't refresh/close the page or the access token is valid.

### Authenticate

First you need to get an authorization code:

```
await oauthClient.requestAuthorizationCode();
```

This will navigate to the auth server where the user is asked to login and acknowledge the request to access the scopes. (So any code following this will never be executed.)

Afterwards, the user is redirected to the `redirectUrl` configured above. The redirect includes an authorization code which you need to grab and then use it to get the tokens with which further requests can be authorized:

```
await oauthClient.receiveCode();
const tokens = await oauthClient.getTokens();
```

This library supports access tokens, refresh tokens, and id tokens.

### Use the tokens

Now you can use the token in order to make requests. There are some mechanisms to help you with that.

#### Automatically Get New Access Token

Instead of checking the validity of an access token all the time, the app might just assume it is valid. When using the `fetch()` API there is a way to automatically get a new access token in case the backend indicates that the access token is no longer valid. Just wrap your `fetch` function like so:

```
window.fetch = oauthClient.makeRetryFetchFunction(window.fetch);
```

This will wrap the original `fetch` function and transparently make it use the refresh token to get a new access token and retry.

#### Use Interceptors

Many frameworks or libraries offer the concept of request/response interceptors. Those are simple functions which may alter [requests](https://developer.mozilla.org/en-US/docs/Web/API/Request) before they are actually sent to the backend as well as the [response](https://developer.mozilla.org/en-US/docs/Web/API/Response) when it comes back. oauth2-pkce offers both for putting the access token in the request and handling errors in the response:

```
// depending on your framework something like
httpClient.registerRequestInterceptor(oauthClient.requestInterceptor);
httpClient.registerResponseInterceptor(oauthClient.responseInterceptor);
// or manually
async function handleRequest(request) {
    request = await oauthClient.requestInterceptor(request);
    ...
    return request;
}
async function handleResponse(response) {
    response = await oauthClient.responseInterceptor(response);
    ...
    return response;
}
```

There is also a shortcut in case your setup doesn't feature interceptors:

```
window.fetch = oauthClient.decorateFetchWithInterceptors(window.fetch);
```

### Check Authorization State

With `oauthClient.isAuthorized()` you can check whether the user has an access token. This does not actually send a request to the backend. It allows you to decide if the user has to be redirected to login.

### Logout

When a user logs out, all tokens need to be dismissed:

```
await oauthClient.reset()
```

This doesn't redirect or do anything else to indicate to the user that they are no longer logged in. That's the responsibility of the app, e. g. to redirect to the login page.

## Storage

OAuth2PKCE holds some state like the current access token. It needs to be persisted in a way that survives reloads because of the redirects during authentication. By default [local storage](https://developer.mozilla.org/en-US/docs/Web/API/Window/localStorage) is used, but you can provide your own implementation, e.g. if you're creating an app and you want to use platform specific storage:

```
import Storage from 'oauth2-pkce';

class MyOwnStorage implements Storage {
    saveState(serializedState: string) { ... // store somewhere }
    loadState() { return ...; // return the stored string }
}

const myOwnStorage = new MyOwnStorage();

const oauthClient = new OAuth2AuthCodePkceClient(config, myOwnStorage);
```

Both methods can by async / return a promise.

## Changelog

### 2.0.0
* Feature: Made the state storage pluggable
* Breaking change: `receiveCode()` and `reset()` are async now

## Acknowledgements

This library is basically a rewrite of https://github.com/BitySA/oauth2-auth-code-pkce/ with the goal of having more maintanable and customizable code.

Development was funded by http://comsulting.de
