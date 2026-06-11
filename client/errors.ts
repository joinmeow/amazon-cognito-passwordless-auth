/**
 * Copyright Amazon.com, Inc. and its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"). You
 * may not use this file except in compliance with the License. A copy of
 * the License is located at
 *
 *     http://aws.amazon.com/apache2.0/
 *
 * or in the "license" file accompanying this file. This file is
 * distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF
 * ANY KIND, either express or implied. See the License for the specific
 * language governing permissions and limitations under the License.
 */

/**
 * Base error class for all FIDO2/WebAuthn related errors
 */
export class Fido2Error extends Error {
  /**
   * User-friendly message suitable for display to end users.
   * Uses passkey terminology and avoids technical jargon.
   */
  public readonly userMessage: string;

  constructor(
    message: string,
    public readonly code: string,
    userMessage?: string,
    public readonly cause?: unknown
  ) {
    super(message);
    this.name = "Fido2Error";
    this.userMessage = userMessage ?? message;

    // Maintains proper stack trace for where our error was thrown (only available on V8)
    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, this.constructor);
    }
  }
}

/**
 * Thrown when WebAuthn operation is cancelled/aborted by user or application
 *
 * Example: User closes passkey dialog, component unmounts during authentication
 */
export class Fido2AbortError extends Fido2Error {
  constructor(
    message = "WebAuthn operation was cancelled",
    userMessage = "Passkey verification was cancelled"
  ) {
    super(message, "WEBAUTHN_ABORTED", userMessage);
    this.name = "Fido2AbortError";
  }
}

/**
 * Thrown when credential operations fail
 *
 * Examples:
 * - No credential returned from browser
 * - Invalid credential format
 * - Credential not found
 *
 * The `code` property discriminates the failure mode:
 * - "CREDENTIAL_NOT_ALLOWED": user cancelled, no local credentials
 *   (mediation: "immediate"), no user gesture, or permission denied
 *   (DOMException NotAllowedError)
 * - "CREDENTIAL_INVALID_STATE": authenticator in invalid state or credential
 *   already registered (DOMException InvalidStateError)
 * - "CREDENTIAL_REQUEST_PENDING": another WebAuthn request is already pending
 *   (DOMException OperationError whose message indicates a pending request,
 *   e.g. Chrome's "A request is already pending"; other OperationErrors map
 *   to the generic fallback)
 * - "CREDENTIAL_ERROR": other credential failures (default)
 */
export class Fido2CredentialError extends Fido2Error {
  constructor(
    message: string,
    cause?: unknown,
    userMessage?: string,
    code = "CREDENTIAL_ERROR"
  ) {
    super(
      message,
      code,
      userMessage ?? "Unable to complete passkey operation",
      cause
    );
    this.name = "Fido2CredentialError";
  }
}

/**
 * Thrown when FIDO2 configuration is missing or invalid
 *
 * Examples:
 * - Missing fido2 config in configure()
 * - Invalid baseUrl or rpId
 */
export class Fido2ConfigError extends Fido2Error {
  constructor(message: string, userMessage?: string) {
    super(
      message,
      "CONFIG_ERROR",
      userMessage ?? "Passkeys are not properly configured"
    );
    this.name = "Fido2ConfigError";
  }
}

/**
 * Thrown when validation of FIDO2 options or responses fails
 *
 * Examples:
 * - Invalid challenge format
 * - Missing required fields in server response
 * - Type mismatch in credential response
 */
export class Fido2ValidationError extends Fido2Error {
  constructor(
    message: string,
    public readonly invalidValue?: unknown,
    userMessage?: string
  ) {
    super(
      message,
      "VALIDATION_ERROR",
      userMessage ?? "Unable to verify passkey",
      invalidValue
    );
    this.name = "Fido2ValidationError";
  }
}

/**
 * Thrown when authentication/authorization fails
 *
 * Examples:
 * - No JWT token available
 * - Token expired
 * - Insufficient permissions
 */
export class Fido2AuthError extends Fido2Error {
  constructor(message: string, userMessage?: string) {
    super(
      message,
      "AUTH_ERROR",
      userMessage ?? "Authentication with passkey failed"
    );
    this.name = "Fido2AuthError";
  }
}

/**
 * Thrown when server/network requests fail
 *
 * Examples:
 * - HTTP error responses
 * - Network timeout
 * - Server unreachable
 */
export class Fido2NetworkError extends Fido2Error {
  constructor(
    message: string,
    public readonly statusCode?: number,
    public readonly response?: unknown,
    userMessage?: string
  ) {
    super(
      message,
      "NETWORK_ERROR",
      userMessage ?? "Unable to connect to passkey service",
      response
    );
    this.name = "Fido2NetworkError";
  }
}

/**
 * Type guard to check if error is a Fido2Error
 */
export function isFido2Error(error: unknown): error is Fido2Error {
  return error instanceof Fido2Error;
}

/**
 * Type guard to check if error is an abort error
 */
export function isFido2AbortError(error: unknown): error is Fido2AbortError {
  return error instanceof Fido2AbortError;
}

/**
 * Type guard to check if error means the WebAuthn ceremony was not allowed:
 * the user cancelled the passkey dialog, no user gesture was present,
 * permission was denied, or (with mediation: "immediate") no local
 * credentials were available.
 *
 * Note: errors thrown by this library are Fido2Error instances, so checking
 * `error.name === "NotAllowedError"` does NOT work — the original
 * DOMException is only preserved in `error.cause`. Use this helper instead,
 * e.g. to fall back to a password form:
 *
 * @example
 * ```typescript
 * try {
 *   await authenticateWithFido2({ mediation: "immediate" }).signedIn;
 * } catch (error) {
 *   if (isFido2NotAllowedError(error)) {
 *     showPasswordForm();
 *   }
 * }
 * ```
 */
export function isFido2NotAllowedError(
  error: unknown
): error is Fido2CredentialError {
  return (
    error instanceof Fido2CredentialError &&
    error.code === "CREDENTIAL_NOT_ALLOWED"
  );
}

/**
 * Helper to convert DOMException (from WebAuthn API) to appropriate Fido2Error
 *
 * Based on WebAuthn Level 2 specification:
 * - navigator.credentials.create() can throw: AbortError, ConstraintError,
 *   InvalidStateError, NotSupportedError, SecurityError, NotAllowedError, UnknownError
 * - navigator.credentials.get() can throw: AbortError, InvalidStateError,
 *   SecurityError, NotAllowedError, UnknownError
 */
export function fromDOMException(error: DOMException): Fido2Error {
  switch (error.name) {
    case "AbortError":
      // User cancelled via AbortController or timeout
      return new Fido2AbortError(
        "WebAuthn operation was aborted",
        "Passkey verification was cancelled"
      );

    case "NotAllowedError":
      // User cancelled the ceremony, or no user gesture, or permission denied,
      // or no local credentials with mediation: "immediate"
      // This is a catch-all covering many scenarios
      // Detect via isFido2NotAllowedError() or code === "CREDENTIAL_NOT_ALLOWED"
      return new Fido2CredentialError(
        "Operation not allowed (user cancelled, no gesture, or permission denied)",
        error,
        "Passkey access was denied. Please try again.",
        "CREDENTIAL_NOT_ALLOWED"
      );

    case "InvalidStateError":
      // For create(): Authenticator recognized entry in excludeCredentials after user consent
      // For get(): Authenticator is in invalid state
      return new Fido2CredentialError(
        "Authenticator is in invalid state or credential already registered",
        error,
        "This passkey is already registered",
        "CREDENTIAL_INVALID_STATE"
      );

    case "OperationError":
      // Not in the WebAuthn spec list, but thrown by Chrome when another
      // WebAuthn request is already pending ("A request is already pending").
      // Browsers also surface OperationError for generic transient or
      // authenticator failures, so only map to CREDENTIAL_REQUEST_PENDING
      // when the message actually indicates a pending/concurrent request;
      // other OperationErrors fall through to the generic fallback below
      if (/pending/i.test(error.message)) {
        return new Fido2CredentialError(
          "Another WebAuthn request is already pending",
          error,
          "Another passkey request is in progress. Please try again.",
          "CREDENTIAL_REQUEST_PENDING"
        );
      }
      break;

    case "NotSupportedError":
      // No pubKeyCredParams had type="public-key", or authenticator doesn't support algorithms
      return new Fido2ConfigError(
        "WebAuthn not supported or requested algorithms not available",
        "Passkeys are not supported on this device"
      );

    case "SecurityError":
      // Invalid domain, rp.id not valid, or related origins validation failed
      return new Fido2ConfigError(
        "Security requirements not met (invalid domain, rp.id mismatch, or HTTPS required)",
        "Passkeys cannot be used on this website"
      );

    case "ConstraintError":
      // residentKey=required but not supported, or userVerification=required but unavailable
      return new Fido2ValidationError(
        "Authenticator constraints not satisfied (resident key or user verification required)",
        error,
        "Your device doesn't support the required security features"
      );

    case "UnknownError":
      // Client-specific error that doesn't fit other categories
      return new Fido2Error(
        "Unknown WebAuthn error occurred",
        "WEBAUTHN_UNKNOWN_ERROR",
        "Something went wrong with your passkey",
        error
      );

  }

  // Catch any other DOMExceptions not in spec
  // (incl. OperationError without a pending-request message)
  return new Fido2Error(
    `WebAuthn operation failed: ${error.message}`,
    "WEBAUTHN_ERROR",
    "Unable to use passkey. Please try again.",
    error
  );
}
