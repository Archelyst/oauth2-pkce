/**
 * OAuth2AuthCodePKCE errors
 */
export class ErrorOAuth2 {
}

/**
 * Some generic, internal errors
 */
// for really unknown errors
export class ErrorUnknown extends ErrorOAuth2 {
    constructor (readonly message) {
        super();
    }
}

export class ErrorNoAccessToken extends ErrorOAuth2 {
}

export class ErrorNoAuthCode extends ErrorOAuth2 {
}

export class ErrorInvalidReturnedStateParam extends ErrorOAuth2 {
}

/**
 * Errors that occur across many endpoints
 */
export class ErrorInvalidScope extends ErrorOAuth2 {
}

export class ErrorInvalidRequest extends ErrorOAuth2 {
}

export class ErrorInvalidToken extends ErrorOAuth2 {
}

/**
 * Authorization grant errors thrown by the redirection from the
 * authorization server
 */
export class ErrorAuthenticationGrant extends ErrorOAuth2 {
}

export class ErrorUnauthorizedClient extends ErrorAuthenticationGrant {
}

export class ErrorAccessDenied extends ErrorAuthenticationGrant {
}

export class ErrorUnsupportedResponseType extends ErrorAuthenticationGrant {
}

export class ErrorServerError extends ErrorAuthenticationGrant {
}

export class ErrorTemporarilyUnavailable extends ErrorAuthenticationGrant {
}

/**
 * Access token response errors
 */
export class ErrorAccessTokenResponse extends ErrorOAuth2 {
}

export class ErrorInvalidClient extends ErrorAccessTokenResponse {
}

export class ErrorInvalidGrant extends ErrorAccessTokenResponse {
}

export class ErrorUnsupportedGrantType extends ErrorAccessTokenResponse {
}

export const RAW_ERROR_TO_ERROR_CLASS_MAP = {
    invalid_request: ErrorInvalidRequest,
    invalid_grant: ErrorInvalidGrant,
    unauthorized_client: ErrorUnauthorizedClient,
    access_denied: ErrorAccessDenied,
    unsupported_response_type: ErrorUnsupportedResponseType,
    invalid_scope: ErrorInvalidScope,
    server_error: ErrorServerError,
    temporarily_unavailable: ErrorTemporarilyUnavailable,
    invalid_client: ErrorInvalidClient,
    unsupported_grant_type: ErrorUnsupportedGrantType,
    invalid_token: ErrorInvalidToken,
};

/**
 * Convert an error string returned from the server to an error object.
 */
export function toErrorObject(rawError: string): ErrorOAuth2 {
    const errorClass = RAW_ERROR_TO_ERROR_CLASS_MAP[rawError];
    return errorClass ? new errorClass() : new ErrorUnknown(rawError);
}

/**
 * WWW-Authenticate error object structure
 */
export class ErrorWWWAuthenticate {
    public realm: string = '';
    public error: string = '';
    public errorDescription: string | undefined;
    public errorUri: string | undefined;
}
