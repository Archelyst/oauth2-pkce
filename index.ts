import {
    ErrorInvalidReturnedStateParam,
    ErrorNoAccessToken,
    ErrorNoAuthCode,
    toErrorObject
} from './errors';
import {
    extractParamFromUrl,
    generatePKCECodeChallengeAndVerifier,
    generateRandomState,
    objectToQueryString,
    parseWwwAuthenticateHeader
} from './helpers';

export * from './errors';

export type ObjStringDict = { [_: string]: string };
export type URL = string;

export interface Configuration {
    authorizationUrl: URL;
    clientId: string;
    onAccessTokenExpiry?: () => Promise<AccessContext>;
    onInvalidGrant?: () => Promise<any> | void;
    onInvalidToken?: () => Promise<any> | void;
    redirectUrl: URL;
    scopes?: string[];
    tokenUrl: URL;
    extraAuthorizationParams?: ObjStringDict;
    extraRefreshParams?: ObjStringDict;
    storeRefreshToken?: boolean;
}

interface State {
    accessToken?: string;
    accessTokenExpiry?: string;
    authorizationCode?: string;
    codeChallenge?: string;
    codeVerifier?: string;
    idToken?: string;
    refreshToken?: string;
    stateQueryParam?: string;
    scopes?: string[];
}

export type Scopes = string[];

export interface AccessContext {
    accessToken?: string;
    idToken?: string;
    refreshToken?: string;
    scopes?: Scopes;
}

export interface TokenResponse {
    accessToken?: string;
    expiresIn?: string;
    scope?: string;
    refreshToken?: string;
    idToken?: string;
}

export interface Storage {
    saveState(serializedState: string): void | Promise<void>;
    loadState(): string | null | Promise<string | null>;
}

const HEADER_AUTHORIZATION = 'Authorization';
const HEADER_WWW_AUTHENTICATE = 'WWW-Authenticate';

/**
 * A sensible length for the state's length, for anti-csrf.
 */
export const RECOMMENDED_STATE_LENGTH = 32;

type FetchFunc = (input: Request | string, ...rest: any[]) => Promise<Response>;


/**
 * OAuth 2.0 client that ONLY supports authorization code flow with PKCE.
 *
 * Many applications structure their OAuth usage in different ways. This class
 * aims to provide both flexible and easy ways to use this configuration of
 * OAuth.
 */
export class OAuth2AuthCodePkceClient {
    readonly config: Configuration;
    private state: State = { };
    private authCodeForAccessTokenPromise?: Promise<TokenResponse>;
    private refreshTokenForAccessTokenPromise?: Promise<TokenResponse>;
    private refreshToken: string;
    private storage: Storage;
    private ready: Promise<void>;
    private setReady: Function;

    constructor(config: Configuration, storage?: Storage) {
        this.config = config;
        this.storage = storage || LocalStorage;
        this.ready = new Promise(resolve => this.setReady = resolve);
        this.recoverState();
    }

    /**
     * Resets the state of the client. Equivalent to "logging out" the user.
     */
    public async reset() {
        this.state = { };
        await this.saveState();
        this.authCodeForAccessTokenPromise = undefined;
        this.refreshTokenForAccessTokenPromise = undefined;
    }

    /**
     * Fetch an authorization code via redirection. In a sense this function
     * doesn't return because of the redirect behavior (uses `location.replace`).
     *
     * @param oneTimeParams A way to specify "one time" query string
     * parameters during the authorization code fetching process, usually for
     * values which need to change at run-time.
     */
    public async requestAuthorizationCode(oneTimeParams?: ObjStringDict) {
        const { clientId, extraAuthorizationParams, redirectUrl, scopes } = this.config;

        const { codeChallenge, codeVerifier } = await generatePKCECodeChallengeAndVerifier();
        const stateQueryParam = generateRandomState(RECOMMENDED_STATE_LENGTH);

        this.state = {
            ...this.state,
            codeChallenge,
            codeVerifier,
            stateQueryParam
        };
        this.saveState();

        let url = this.config.authorizationUrl
            + '?response_type=code&'
            + `client_id=${encodeURIComponent(clientId)}&`
            + `redirect_uri=${encodeURIComponent(redirectUrl)}&`
            + `state=${stateQueryParam}&`
            + `code_challenge=${encodeURIComponent(codeChallenge)}&`
            + 'code_challenge_method=S256';

        if (scopes) {
            url += `&scope=${encodeURIComponent(scopes.join(' '))}`;
        }

        if (extraAuthorizationParams || oneTimeParams) {
            const extraParameters: ObjStringDict = {
                ...extraAuthorizationParams,
                ...oneTimeParams
            };
            url += `&${objectToQueryString(extraParameters)}`;
        }

        location.replace(url);
    }

    /**
     * Check if it looks like we are coming back from requesting an auth code.
     */
    public isReturningFromAuthServer(): boolean {
        return !!extractParamFromUrl('code', location.href);
    }

    /**
     * Read the code from the URL and store it.
     */
    public async receiveCode() {
        await this.ready;
        const error = extractParamFromUrl('error', location.href);
        if (error) {
            throw toErrorObject(error);
        }

        const stateQueryParam = extractParamFromUrl('state', location.href);
        if (stateQueryParam !== this.state.stateQueryParam) {
            console.warn('"state" parameter doesn\'t match the one sent! ' +
                'Possible malicious activity.');
            throw new ErrorInvalidReturnedStateParam();
        }

        this.state.authorizationCode = extractParamFromUrl('code', location.href);
        if (!this.state.authorizationCode) {
            throw new ErrorNoAuthCode();
        }
        this.saveState();
    }

    /**
     * Using a previously fetched authorization code try to get the auth tokens.
     * If there is no authorization code return the previously fetched access token.
     */
    public async getTokens(): Promise<AccessContext> {
        const {
            accessToken,
            authorizationCode,
            idToken,
            refreshToken,
            scopes
        } = this.state;

        if (authorizationCode) {
            return this.exchangeAuthCodeForAccessToken();
        }

        if (!accessToken) {
            throw new ErrorNoAccessToken();
        }

        if (this.isAccessTokenExpired()) {
            if (this.config.onAccessTokenExpiry) {
                return this.config.onAccessTokenExpiry();
            }
        }

        return Promise.resolve({ accessToken, idToken, refreshToken, scopes });
    }

    /**
     * Fetch an access token from the remote service.
     * This gets implicitly called by `getTokens()`.
     */
    public async exchangeAuthCodeForAccessToken(): Promise<AccessContext> {
        if (!this.authCodeForAccessTokenPromise) {
            this.authCodeForAccessTokenPromise = this.fetchAccessTokenUsingCode();
        }
        const tokenResponse = await this.authCodeForAccessTokenPromise;
        this.authCodeForAccessTokenPromise = undefined;
        this.state.authorizationCode = undefined;
        return this.setTokens(tokenResponse);
    }

    /**
     * Refresh an access token from the remote service.
     */
    public async exchangeRefreshTokenForAccessToken(): Promise<AccessContext> {
        if (!this.refreshTokenForAccessTokenPromise) {
            this.refreshTokenForAccessTokenPromise = this.fetchAccessTokenUsingRefreshToken();
        }
        const tokenResponse = await this.refreshTokenForAccessTokenPromise;
        this.refreshTokenForAccessTokenPromise = undefined;
        return this.setTokens(tokenResponse);
    }

    /**
     * Make a `fetch()` function that retries in case an access token is not valid any more.
     */
    public makeRetryFetchFunction(fetchFunc: FetchFunc): FetchFunc {
        return async (input: Request | string, ...rest): Promise<Response> => {
            const response = await fetchFunc(input, ...rest);
            if (response.status === 401) {
                const authenticateHeader = response.headers.get(
                    HEADER_WWW_AUTHENTICATE.toLowerCase()
                );
                if (authenticateHeader) {
                    const error = parseWwwAuthenticateHeader(authenticateHeader).error;
                    if (error === 'invalid_token') {
                        await this.exchangeRefreshTokenForAccessToken();
                        input = await this.requestInterceptor(input as Request);
                        return fetchFunc(input, ...rest);
                    }
                }
            }
            return response;
        };
    }

    /**
     * Make a `fetch()` function that has both the `requestInterceptor` and the
     * `responseInterceptor` attached, which add the OAuth logic to all fetch requests
     * and handle / translate errors.
     * This function can be used if the host application / framework does not provide
     * a request / response processing mechanism.
     */
    public decorateFetchWithInterceptors(fetchFunc: FetchFunc): FetchFunc {
        return async (input: Request | string, ...rest): Promise<Response> => {
            if (typeof input === 'string') {
                input = new Request(input);
            }
            input = await this.requestInterceptor(input);
            const response = await fetchFunc(input, ...rest);
            return this.responseInterceptor(response);
        };
    }

    /**
     * Put the access token on `fetch()` `Request`s. Gets a fresh access token
     * if the current one is invalid.
     * This function is meant to be wired into the request processing of an app / a framework.
     *
     * @see decorateFetchWithInterceptors
     */
    public async requestInterceptor(request: Request) {
        const tokenContext = await this.getTokens();
        request.headers.set(HEADER_AUTHORIZATION, `Bearer ${tokenContext.accessToken}`);
        return request;
    }

    /**
     * Handle auth related errors in `fetch()` `Response`s.
     * This function is meant to be wired into the response processing of an app / a framework.
     *
     * @see decorateFetchWithInterceptors
     */
    public async responseInterceptor(response: Response) {
        if (response.status !== 401) {
            return response;
        }
        const authenticateHeader = response.headers.get(HEADER_WWW_AUTHENTICATE.toLowerCase());
        if (authenticateHeader) {
            const error = parseWwwAuthenticateHeader(authenticateHeader).error;
            if (error === 'invalid_grant' && this.config.onInvalidGrant) {
                await this.config.onInvalidGrant();
            }
            if (error === 'invalid_token' && this.config.onInvalidToken) {
                await this.config.onInvalidToken();
            }
            throw toErrorObject(error);
        }
        return response;
    }

    /**
     * Get the scopes that were granted by the authorization server.
     */
    public getGrantedScopes(): Scopes | undefined {
        return this.state.scopes;
    }

    /**
     * Tells if the client is authorized or not. This means the client has at
     * least once successfully fetched an access token. The access token could be
     * expired.
     */
    public isAuthorized(): boolean {
        return !!this.state.accessToken;
    }

    /**
     * Checks to see if the access token has expired.
     */
    public isAccessTokenExpired(): boolean {
        const { accessTokenExpiry } = this.state;
        return Boolean(accessTokenExpiry && (new Date()) >= (new Date(accessTokenExpiry)));
    }

    /**
     * Use the current grant code to fetch a fresh authorization token.
     */
    private async fetchAccessTokenUsingCode() {
        const { authorizationCode, codeVerifier = '' } = this.state;
        const { clientId, redirectUrl} = this.config;

        if (!codeVerifier) {
            console.warn('No code verifier is being sent.');
        }
        else if (!authorizationCode) {
            console.warn('No authorization grant code is being passed.');
        }

        const url = this.config.tokenUrl;
        const body = 'grant_type=authorization_code&'
            + `code=${encodeURIComponent(authorizationCode || '')}&`
            + `redirect_uri=${encodeURIComponent(redirectUrl)}&`
            + `client_id=${encodeURIComponent(clientId)}&`
            + `code_verifier=${codeVerifier}`;
        return this.makeTokenRequest(url, body);
    }

    /**
     * Fetch a new access token using the refresh token.
     */
    private fetchAccessTokenUsingRefreshToken() {
        const { extraRefreshParams, clientId, tokenUrl } = this.config;
        const { refreshToken } = this.state;

        if (!refreshToken) {
            console.warn('No refresh token is present.');
        }

        const url = tokenUrl;
        let body = 'grant_type=refresh_token&'
            + `refresh_token=${refreshToken}&`
            + `client_id=${clientId}`;

        if (extraRefreshParams) {
            body = `${url}&${objectToQueryString(extraRefreshParams)}`;
        }
        return this.makeTokenRequest(url, body);
    }

    private async makeTokenRequest(url: string, body: string): Promise<TokenResponse> {
        const tokenResponse = await fetch(url, {
            method: 'POST',
            body,
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded'
            }
        });
        const jsonContent = await tokenResponse.json();
        if (!tokenResponse.ok) {
            if (jsonContent.error === 'invalid_grant' && this.config.onInvalidGrant) {
                await this.config.onInvalidGrant();
            }
            throw toErrorObject(jsonContent.error);
        }
        const { access_token, expires_in, id_token, refresh_token, scope } = jsonContent;
        return {
            accessToken: access_token,
            expiresIn: expires_in,
            idToken: id_token,
            refreshToken: refresh_token,
            scope
        };
    }

    private async setTokens(tokenResponse: TokenResponse): Promise<AccessContext> {
        const { accessToken, expiresIn, idToken, refreshToken, scope } = tokenResponse;
        this.state.accessToken = accessToken;
        this.state.accessTokenExpiry = (new Date(Date.now() + (parseInt(expiresIn, 10) * 1000)))
            .toString();
        if (idToken) {
            this.state.idToken = idToken;
        }
        if (refreshToken) {
            this.state.refreshToken = refreshToken;
        }
        if (scope) {
            // Multiple scopes are passed and delimited by spaces,
            // despite using the singular name "scope".
            this.state.scopes = scope.split(' ');
        }
        await this.saveState();
        return {
            accessToken: this.state.accessToken,
            idToken: this.state.idToken,
            refreshToken: this.state.refreshToken,
            scopes: scope ? this.state.scopes : []
          };
    }

    private async recoverState() {
        this.state = JSON.parse(await this.storage.loadState() || '{}');
        this.setReady();
        if (!this.config.storeRefreshToken) {
            this.state.refreshToken = this.refreshToken;
        }
    }

    private async saveState() {
        this.refreshToken = this.state.refreshToken;
        const state = { ...this.state };
        if (!this.config.storeRefreshToken) {
            delete state.refreshToken;
        }
        await this.storage.saveState(JSON.stringify(state));
    }
}


/**
 * To store the OAuth client's data between websites due to redirection.
 */
const LOCALSTORAGE_STATE = 'oauth2authcodepkce-state';

const LocalStorage: Storage = {
    saveState: (serializedState: string) => localStorage.setItem(LOCALSTORAGE_STATE, serializedState),
    loadState: () => localStorage.getItem(LOCALSTORAGE_STATE)
};
