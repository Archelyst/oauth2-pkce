import { describe, it, expect } from 'vitest';
import {
    toErrorObject,
    ErrorUnknown,
    ErrorInvalidRequest,
    ErrorInvalidGrant,
    ErrorInvalidToken,
    ErrorInvalidClient,
    ErrorAccessDenied,
    ErrorUnauthorizedClient,
    ErrorUnsupportedResponseType,
    ErrorUnsupportedGrantType,
    ErrorInvalidScope,
    ErrorServerError,
    ErrorTemporarilyUnavailable,
    RAW_ERROR_TO_ERROR_CLASS_MAP,
} from '../errors';

describe('toErrorObject', () => {
    it.each(Object.entries(RAW_ERROR_TO_ERROR_CLASS_MAP))(
        'maps "%s" to the correct error class',
        (rawError, ErrorClass) => {
            expect(toErrorObject(rawError)).toBeInstanceOf(ErrorClass);
        }
    );

    it('returns ErrorUnknown for unrecognised error strings', () => {
        const err = toErrorObject('something_completely_unknown');
        expect(err).toBeInstanceOf(ErrorUnknown);
        expect((err as ErrorUnknown).message).toBe('something_completely_unknown');
    });

    it('maps all expected OAuth error codes', () => {
        expect(toErrorObject('invalid_request')).toBeInstanceOf(ErrorInvalidRequest);
        expect(toErrorObject('invalid_grant')).toBeInstanceOf(ErrorInvalidGrant);
        expect(toErrorObject('invalid_token')).toBeInstanceOf(ErrorInvalidToken);
        expect(toErrorObject('invalid_client')).toBeInstanceOf(ErrorInvalidClient);
        expect(toErrorObject('access_denied')).toBeInstanceOf(ErrorAccessDenied);
        expect(toErrorObject('unauthorized_client')).toBeInstanceOf(ErrorUnauthorizedClient);
        expect(toErrorObject('unsupported_response_type')).toBeInstanceOf(ErrorUnsupportedResponseType);
        expect(toErrorObject('unsupported_grant_type')).toBeInstanceOf(ErrorUnsupportedGrantType);
        expect(toErrorObject('invalid_scope')).toBeInstanceOf(ErrorInvalidScope);
        expect(toErrorObject('server_error')).toBeInstanceOf(ErrorServerError);
        expect(toErrorObject('temporarily_unavailable')).toBeInstanceOf(ErrorTemporarilyUnavailable);
    });
});
