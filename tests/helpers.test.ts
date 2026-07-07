import { describe, it, expect } from 'vitest';
import {
    extractParamFromUrl,
    generatePKCECodeChallengeAndVerifier,
    generateRandomState,
    objectToQueryString,
    parseWwwAuthenticateHeader,
    RECOMMENDED_CODE_VERIFIER_LENGTH,
} from '../helpers';

describe('parseWwwAuthenticateHeader', () => {
    it('parses realm and error', () => {
        const result = parseWwwAuthenticateHeader('Bearer realm="example.com",error="invalid_token"');
        expect(result.realm).toBe('example.com');
        expect(result.error).toBe('invalid_token');
    });

    it('parses error_description and error_uri', () => {
        const result = parseWwwAuthenticateHeader(
            'Bearer realm="example.com",error="invalid_token",error_description="Token expired",error_uri="https://example.com/errors"'
        );
        expect(result.errorDescription).toBe('Token expired');
        expect(result.errorUri).toBe('https://example.com/errors');
    });
});

describe('extractParamFromUrl', () => {
    it('extracts a query parameter', () => {
        expect(extractParamFromUrl('code', 'https://example.com?code=abc123')).toBe('abc123');
    });

    it('extracts one of multiple parameters', () => {
        expect(extractParamFromUrl('state', 'https://example.com?code=abc&state=xyz')).toBe('xyz');
    });

    it('returns undefined when the parameter is absent', () => {
        expect(extractParamFromUrl('code', 'https://example.com?state=xyz')).toBeUndefined();
    });

    it('returns undefined for URLs without a query string', () => {
        expect(extractParamFromUrl('code', 'https://example.com')).toBeUndefined();
    });

    it('ignores URL fragments (SPA hash routing)', () => {
        expect(extractParamFromUrl('code', 'https://example.com?code=abc#/home')).toBe('abc');
    });

    it('decodes percent-encoded values', () => {
        expect(extractParamFromUrl('redirect', 'https://example.com?redirect=https%3A%2F%2Fother.com')).toBe('https://other.com');
    });
});

describe('objectToQueryString', () => {
    it('converts an object to key=value pairs joined by &', () => {
        expect(objectToQueryString({ foo: 'bar', baz: 'qux' })).toBe('foo=bar&baz=qux');
    });

    it('percent-encodes special characters in values', () => {
        expect(objectToQueryString({ url: 'https://example.com/path' }))
            .toBe('url=https%3A%2F%2Fexample.com%2Fpath');
    });
});

describe('generateRandomState', () => {
    it('returns a string of the requested length', () => {
        expect(generateRandomState(32)).toHaveLength(32);
        expect(generateRandomState(16)).toHaveLength(16);
    });

    it('only contains valid PKCE charset characters', () => {
        expect(generateRandomState(200)).toMatch(/^[A-Za-z0-9\-._~]+$/);
    });

    it('produces different values on each call', () => {
        expect(generateRandomState(32)).not.toBe(generateRandomState(32));
    });
});

describe('generatePKCECodeChallengeAndVerifier', () => {
    it('returns a non-empty verifier and challenge', async () => {
        const { codeVerifier, codeChallenge } = await generatePKCECodeChallengeAndVerifier();
        expect(codeVerifier).toBeTruthy();
        expect(codeChallenge).toBeTruthy();
    });

    it('verifier only contains base64url characters', async () => {
        const { codeVerifier } = await generatePKCECodeChallengeAndVerifier();
        expect(codeVerifier).toMatch(/^[A-Za-z0-9\-_]+$/);
    });

    it('challenge is the S256 (base64url SHA-256) of the verifier', async () => {
        const { codeVerifier, codeChallenge } = await generatePKCECodeChallengeAndVerifier();

        const buffer = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(codeVerifier));
        const hash = new Uint8Array(buffer);
        let binary = '';
        for (let i = 0; i < hash.byteLength; i++) binary += String.fromCharCode(hash[i]);
        const expected = btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');

        expect(codeChallenge).toBe(expected);
    });

    it('produces different values on each call', async () => {
        const a = await generatePKCECodeChallengeAndVerifier();
        const b = await generatePKCECodeChallengeAndVerifier();
        expect(a.codeVerifier).not.toBe(b.codeVerifier);
    });

    it(`verifier encodes ${RECOMMENDED_CODE_VERIFIER_LENGTH} random bytes`, async () => {
        // base64url of 96 bytes → 128 characters (without padding)
        const { codeVerifier } = await generatePKCECodeChallengeAndVerifier();
        expect(codeVerifier.length).toBe(128);
    });
});
