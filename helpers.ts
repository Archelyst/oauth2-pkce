import { ErrorWWWAuthenticate } from './errors';

/**
 * The maximum length for a code verifier for the best security we can offer.
 * Please note the NOTE section of RFC 7636 § 4.1 - the length must be >= 43,
 * but <= 128, **after** base64 url encoding. This means 32 code verifier bytes
 * encoded will be 43 bytes, or 96 bytes encoded will be 128 bytes. So 96 bytes
 * is the highest valid value that can be used.
 */
export const RECOMMENDED_CODE_VERIFIER_LENGTH = 96;

/**
 * Character set to generate code verifier defined in rfc7636.
 */
const PKCE_CHARSET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~';

/**
 * Create on object from a WWW-Authenticate header:
 * `Bearer realm="example.com",error="invalid_client"` becomes
 * `{ realm: "example.com", error: "invalid_client" }`.
 */
export function parseWwwAuthenticateHeader(header: string): ErrorWWWAuthenticate {
    const headerMap = header
        .slice('Bearer '.length)
        .replace(/"/g, '')
        .split(',')
        .map(pair => {
            const [key, value] = pair.trim().split('=');
            return { [key]: value};
        })
        .reduce((prev, next) => ({ ...prev, ...next}), { });
    return {
        realm: headerMap.realm,
        error: headerMap.error,
        errorDescription: headerMap.error_description,
        errorUri: headerMap.error_uri
    };
}

/**
 * Implements *base64url-encode* (RFC 4648 § 5) without padding, which is NOT
 * the same as regular base64 encoding.
 */
function base64urlEncode(value: string): string {
    let base64 = btoa(value);
    base64 = base64.replace(/\+/g, '-');
    base64 = base64.replace(/\//g, '_');
    base64 = base64.replace(/=/g, '');
    return base64;
}

/**
 * Extract a parameter from a query string
 */
export function extractParamFromUrl(param: string, url: string): string | undefined {
    let queryString = url.split('?');
    if (queryString.length < 2) {
        return undefined;
    }
    // remove URL fragments that SPAs usually use
    queryString = queryString[1].split('#');
    const parts = queryString[0].split('&');
    for (const part of parts) {
        const [key, value] = part.split('=');
        if (key === param) {
            return decodeURIComponent(value);
        }
    }
}

/**
 * Convert the keys and values of an object to a url query string
 */
export function objectToQueryString(dict): string {
    return Object.entries(dict).map(
        ([key, val]: [string, string]) => `${key}=${encodeURIComponent(val)}`
    ).join('&');
}

/**
 * Generate a code_verifier and code_challenge, as specified in rfc7636.
 */
export async function generatePKCECodeChallengeAndVerifier() {
    const output = new Uint32Array(RECOMMENDED_CODE_VERIFIER_LENGTH);
    crypto.getRandomValues(output);
    const codeVerifier = base64urlEncode(Array
        .from(output)
        .map((num: number) => PKCE_CHARSET[num % PKCE_CHARSET.length])
        .join(''));
    const buffer = await crypto
        .subtle
        .digest('SHA-256', (new TextEncoder()).encode(codeVerifier));
    const hash = new Uint8Array(buffer);
    let binary = '';
    const hashLength = hash.byteLength;
    for (let i: number = 0; i < hashLength; i++) {
        binary += String.fromCharCode(hash[i]);
    }
    const codeChallenge = base64urlEncode(binary);
    return { codeChallenge, codeVerifier };
}

/**
 * Generate random state to be passed for anti-csrf.
 */
export function generateRandomState(lengthOfState: number): string {
    const output = new Uint32Array(lengthOfState);
    crypto.getRandomValues(output);
    return Array
        .from(output)
        .map((num: number) => PKCE_CHARSET[num % PKCE_CHARSET.length])
        .join('');
}
