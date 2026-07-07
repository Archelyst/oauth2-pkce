import { beforeEach, describe, expect, it, vi } from 'vitest';
import {
    ErrorAccessTokenExpired,
    ErrorInvalidReturnedStateParam,
    ErrorNoAccessToken,
    ErrorNoAuthCode,
    OAuth2AuthCodePkceClient,
} from '../index';

const STATE_KEY = 'oauth2authcodepkce-state';

const baseConfig = {
    authorizationUrl: 'https://auth.example.com/authorize',
    tokenUrl: 'https://auth.example.com/token',
    clientId: 'test-client',
    redirectUrl: 'https://app.example.com/callback',
};

/** Create a client and wait for async state recovery to complete. */
async function makeClient(
    config = baseConfig,
    initialState?: object
): Promise<OAuth2AuthCodePkceClient> {
    if (initialState !== undefined) {
        localStorage.setItem(STATE_KEY, JSON.stringify(initialState));
    }
    const client = new OAuth2AuthCodePkceClient(config);
    await Promise.resolve(); // let recoverState microtask settle
    return client;
}

function setLocation(url: string) {
    vi.stubGlobal('location', { href: url, replace: vi.fn() });
}

beforeEach(() => {
    localStorage.clear();
    vi.restoreAllMocks();
    setLocation('https://app.example.com/');
});

// ---------------------------------------------------------------------------

describe('isAuthorized', () => {
    it('returns false with no stored token', async () => {
        const client = await makeClient();
        expect(client.isAuthorized()).toBe(false);
    });

    it('returns true when an access token is stored', async () => {
        const client = await makeClient(baseConfig, { accessToken: 'tok' });
        expect(client.isAuthorized()).toBe(true);
    });
});

// ---------------------------------------------------------------------------

describe('isAccessTokenExpired', () => {
    it('returns false when no expiry is set', async () => {
        const client = await makeClient(baseConfig, { accessToken: 'tok' });
        expect(client.isAccessTokenExpired()).toBe(false);
    });

    it('returns true for a past expiry', async () => {
        const client = await makeClient(baseConfig, {
            accessToken: 'tok',
            accessTokenExpiry: new Date(Date.now() - 1000).toString(),
        });
        expect(client.isAccessTokenExpired()).toBe(true);
    });

    it('returns false for a future expiry', async () => {
        const client = await makeClient(baseConfig, {
            accessToken: 'tok',
            accessTokenExpiry: new Date(Date.now() + 3_600_000).toString(),
        });
        expect(client.isAccessTokenExpired()).toBe(false);
    });
});

// ---------------------------------------------------------------------------

describe('reset', () => {
    it('clears the stored state', async () => {
        const client = await makeClient(baseConfig, { accessToken: 'tok' });
        await client.reset();
        expect(client.isAuthorized()).toBe(false);
        expect(localStorage.getItem(STATE_KEY)).toBe('{}');
    });
});

// ---------------------------------------------------------------------------

describe('requestAuthorizationCode', () => {
    it('redirects to the authorization URL', async () => {
        const client = await makeClient();
        await client.requestAuthorizationCode();
        expect(location.replace).toHaveBeenCalledWith(
            expect.stringContaining(baseConfig.authorizationUrl)
        );
    });

    it('includes required PKCE and OAuth parameters', async () => {
        const client = await makeClient();
        await client.requestAuthorizationCode();
        const url: string = vi.mocked(location.replace).mock.calls[0][0] as string;
        expect(url).toContain('response_type=code');
        expect(url).toContain('code_challenge_method=S256');
        expect(url).toContain(`client_id=${baseConfig.clientId}`);
        expect(url).toContain('code_challenge=');
        expect(url).toContain('state=');
    });

    it('includes scopes when configured', async () => {
        const client = await makeClient({ ...baseConfig, scopes: ['openid', 'profile'] });
        await client.requestAuthorizationCode();
        const url: string = vi.mocked(location.replace).mock.calls[0][0] as string;
        expect(url).toContain('scope=openid%20profile');
    });

    it('appends oneTimeParams to the URL', async () => {
        const client = await makeClient();
        await client.requestAuthorizationCode({ prompt: 'login' });
        const url: string = vi.mocked(location.replace).mock.calls[0][0] as string;
        expect(url).toContain('prompt=login');
    });

    it('saves state before redirecting (ensures async storage is flushed)', async () => {
        const saved: string[] = [];
        // Truly async storage: save resolves on next macrotask, simulating IndexedDB
        const storage = {
            saveState: (s: string) => new Promise<void>(resolve => setTimeout(() => {
                saved.push(s);
                resolve();
            }, 0)),
            loadState: () => Promise.resolve(null),
        };
        const client = new OAuth2AuthCodePkceClient(baseConfig, storage);
        await client.requestAuthorizationCode();
        // If saveState was awaited, saved[] is populated before location.replace
        expect(saved.length).toBeGreaterThan(0);
        const state = JSON.parse(saved[saved.length - 1]);
        expect(state.codeVerifier).toBeTruthy();
    });
});

// ---------------------------------------------------------------------------

describe('isReturningFromAuthServer', () => {
    it('returns true when a "code" param is present', async () => {
        setLocation('https://app.example.com/callback?code=abc&state=xyz');
        const client = await makeClient();
        expect(client.isReturningFromAuthServer()).toBe(true);
    });

    it('returns false when no "code" param is present', async () => {
        const client = await makeClient();
        expect(client.isReturningFromAuthServer()).toBe(false);
    });
});

// ---------------------------------------------------------------------------

describe('receiveCode', () => {
    it('stores the authorization code from the URL', async () => {
        const stateParam = 'test-state-abc';
        setLocation(`https://app.example.com/callback?code=auth-code-xyz&state=${stateParam}`);
        const client = await makeClient(baseConfig, { stateQueryParam: stateParam });
        await client.receiveCode();
        // After receiving the code the client has an auth code but no access token yet
        expect(client.isAuthorized()).toBe(false);
    });

    it('throws ErrorInvalidReturnedStateParam on state mismatch', async () => {
        setLocation('https://app.example.com/callback?code=abc&state=wrong');
        const client = await makeClient(baseConfig, { stateQueryParam: 'expected' });
        await expect(client.receiveCode()).rejects.toBeInstanceOf(ErrorInvalidReturnedStateParam);
    });

    it('throws ErrorNoAuthCode when "code" is absent', async () => {
        const stateParam = 'test-state';
        setLocation(`https://app.example.com/callback?state=${stateParam}`);
        const client = await makeClient(baseConfig, { stateQueryParam: stateParam });
        await expect(client.receiveCode()).rejects.toBeInstanceOf(ErrorNoAuthCode);
    });
});

// ---------------------------------------------------------------------------

describe('getTokens', () => {
    it('throws ErrorNoAccessToken when no token exists', async () => {
        const client = await makeClient();
        await expect(client.getTokens()).rejects.toBeInstanceOf(ErrorNoAccessToken);
    });

    it('throws ErrorAccessTokenExpired when the token has expired', async () => {
        const client = await makeClient(baseConfig, {
            accessToken: 'old',
            accessTokenExpiry: new Date(Date.now() - 1000).toString(),
        });
        await expect(client.getTokens()).rejects.toBeInstanceOf(ErrorAccessTokenExpired);
    });

    it('calls onAccessTokenExpiry when configured and token is expired', async () => {
        const onExpiry = vi.fn().mockResolvedValue({ accessToken: 'refreshed' });
        const client = await makeClient(
            { ...baseConfig, onAccessTokenExpiry: onExpiry },
            { accessToken: 'old', accessTokenExpiry: new Date(Date.now() - 1000).toString() }
        );
        const result = await client.getTokens();
        expect(onExpiry).toHaveBeenCalled();
        expect(result.accessToken).toBe('refreshed');
    });

    it('returns the stored token when valid', async () => {
        const client = await makeClient(baseConfig, {
            accessToken: 'valid-token',
            accessTokenExpiry: new Date(Date.now() + 3_600_000).toString(),
        });
        const tokens = await client.getTokens();
        expect(tokens.accessToken).toBe('valid-token');
    });

    it('exchanges auth code for tokens when a code is stored', async () => {
        vi.stubGlobal('fetch', vi.fn().mockResolvedValue({
            ok: true,
            json: () => Promise.resolve({ access_token: 'new-token', expires_in: 3600 }),
        }));
        const client = await makeClient(baseConfig, {
            authorizationCode: 'code-xyz',
            codeVerifier: 'verifier-xyz',
        });
        const tokens = await client.getTokens();
        expect(tokens.accessToken).toBe('new-token');
    });

    it('does not set an expiry when the server omits expires_in', async () => {
        vi.stubGlobal('fetch', vi.fn().mockResolvedValue({
            ok: true,
            json: () => Promise.resolve({ access_token: 'no-expiry-token' }),
        }));
        const client = await makeClient(baseConfig, {
            authorizationCode: 'code-xyz',
            codeVerifier: 'verifier-xyz',
        });
        await client.getTokens();
        // Without a guard, parseInt(undefined) = NaN → "Invalid Date" → isAccessTokenExpired()
        // would return false but accessTokenExpiry would be the string "Invalid Date".
        expect(client.isAccessTokenExpired()).toBe(false);
        // Verify the expiry was not stored as an invalid date string
        const stored = JSON.parse(localStorage.getItem('oauth2authcodepkce-state') ?? '{}');
        expect(stored.accessTokenExpiry).toBeUndefined();
    });
});

// ---------------------------------------------------------------------------

describe('exchangeRefreshTokenForAccessToken', () => {
    it('sends the refresh token to the token endpoint', async () => {
        const mockFetch = vi.fn().mockResolvedValue({
            ok: true,
            json: () => Promise.resolve({ access_token: 'refreshed', expires_in: 3600 }),
        });
        vi.stubGlobal('fetch', mockFetch);

        // storeRefreshToken: true so the token survives recoverState
        const client = await makeClient(
            { ...baseConfig, storeRefreshToken: true },
            { refreshToken: 'rt-123' }
        );
        const tokens = await client.exchangeRefreshTokenForAccessToken();

        expect(tokens.accessToken).toBe('refreshed');
        const body: string = mockFetch.mock.calls[0][1].body;
        expect(body).toContain('grant_type=refresh_token');
        expect(body).toContain('refresh_token=rt-123');
        expect(body).toContain(`client_id=${baseConfig.clientId}`);
    });

    it('appends extraRefreshParams without overwriting the base body', async () => {
        const mockFetch = vi.fn().mockResolvedValue({
            ok: true,
            json: () => Promise.resolve({ access_token: 'tok', expires_in: 3600 }),
        });
        vi.stubGlobal('fetch', mockFetch);

        const client = await makeClient(
            { ...baseConfig, storeRefreshToken: true, extraRefreshParams: { audience: 'api.example.com' } },
            { refreshToken: 'rt-456' }
        );
        await client.exchangeRefreshTokenForAccessToken();

        const body: string = mockFetch.mock.calls[0][1].body;
        expect(body).toContain('grant_type=refresh_token');   // not replaced by URL
        expect(body).toContain('refresh_token=rt-456');
        expect(body).toContain('audience=api.example.com');
    });
});

// ---------------------------------------------------------------------------

describe('responseInterceptor', () => {
    it('passes through non-401 responses unchanged', async () => {
        const client = await makeClient();
        const response = new Response('ok', { status: 200 });
        await expect(client.responseInterceptor(response)).resolves.toBe(response);
    });

    it('throws on 401 with invalid_token', async () => {
        const client = await makeClient();
        const response = new Response(null, {
            status: 401,
            headers: { 'WWW-Authenticate': 'Bearer realm="x",error="invalid_token"' },
        });
        await expect(client.responseInterceptor(response)).rejects.toBeDefined();
    });

    it('calls onInvalidGrant and throws on 401 with invalid_grant', async () => {
        const onInvalidGrant = vi.fn();
        const client = await makeClient({ ...baseConfig, onInvalidGrant });
        const response = new Response(null, {
            status: 401,
            headers: { 'WWW-Authenticate': 'Bearer realm="x",error="invalid_grant"' },
        });
        await expect(client.responseInterceptor(response)).rejects.toBeDefined();
        expect(onInvalidGrant).toHaveBeenCalled();
    });
});

// ---------------------------------------------------------------------------

describe('custom storage', () => {
    it('uses the provided storage implementation', async () => {
        let stored = '';
        const storage = {
            saveState: (s: string) => { stored = s; },
            loadState: () => stored || null,
        };
        const client = new OAuth2AuthCodePkceClient(baseConfig, storage);
        await Promise.resolve();
        await client.reset();
        expect(stored).toBe('{}');
    });
});
