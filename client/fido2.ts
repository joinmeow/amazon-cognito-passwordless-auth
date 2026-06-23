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
import { IdleState, BusyState, busyState, TokensFromSignIn } from "./model.js";
import { processTokens } from "./common.js";
import {
  assertIsChallengeResponse,
  isAuthenticatedResponse,
  handleAuthResponse,
  initiateAuth,
  respondToAuthChallenge,
} from "./cognito-api.js";
import {
  parseJwtPayload,
  throwIfNot2xx,
  bufferFromBase64Url,
  bufferToBase64Url,
  redactTokensFromObject,
} from "./util.js";
import { configure } from "./config.js";
import { retrieveTokens, retrieveDeviceKey } from "./storage.js";
import { CognitoIdTokenPayload } from "./jwt-model.js";
import { createDeviceSrpAuthHandler } from "./device.js";
import {
  Fido2CredentialError,
  Fido2ConfigError,
  Fido2ValidationError,
  Fido2AuthError,
  Fido2AbortError,
  fromDOMException,
  isFido2AbortError,
} from "./errors.js";

// Enhanced type definitions for mediation support
export type MediationMode =
  | "conditional"
  | "immediate"
  | "optional"
  | "required"
  | "silent";

/**
 * WebAuthn Client Capabilities as defined in the W3C spec.
 * @see https://w3c.github.io/webauthn/#sctn-client-capabilities
 */
export interface WebAuthnClientCapabilities {
  /** Client can create discoverable credentials */
  conditionalCreate?: boolean;
  /** Client can authenticate using discoverable credentials (autofill) */
  conditionalGet?: boolean;
  /** Client supports hybrid transport (Bluetooth, NFC, USB) */
  hybridTransport?: boolean;
  /** Client has passkey platform authenticator with MFA support */
  passkeyPlatformAuthenticator?: boolean;
  /** Client has user-verifying platform authenticator */
  userVerifyingPlatformAuthenticator?: boolean;
  /** Client supports Related Origin Requests */
  relatedOrigins?: boolean;
  /** Client supports signalAllAcceptedCredentials() */
  signalAllAcceptedCredentials?: boolean;
  /** Client supports signalCurrentUserDetails() */
  signalCurrentUserDetails?: boolean;
  /** Client supports signalUnknownCredential() */
  signalUnknownCredential?: boolean;
  /** Chrome-specific: immediate mediation support (Chrome 139+, origin trial) */
  immediateGet?: boolean;
  /** Extension support: prefixed with 'extension:' */
  [key: `extension:${string}`]: boolean | undefined;
}

/**
 * Extended PublicKeyCredential interface with getClientCapabilities.
 * @see https://w3c.github.io/webauthn/#sctn-client-capabilities
 */
interface PublicKeyCredentialWithCapabilities {
  getClientCapabilities(): Promise<WebAuthnClientCapabilities>;
}

/**
 * Type guard to check if PublicKeyCredential has getClientCapabilities.
 */
function hasGetClientCapabilities(
  pkc: typeof PublicKeyCredential
): pkc is typeof PublicKeyCredential & PublicKeyCredentialWithCapabilities {
  return (
    "getClientCapabilities" in pkc &&
    typeof pkc.getClientCapabilities === "function"
  );
}

/**
 * Get WebAuthn client capabilities with proper type safety.
 * Returns null if getClientCapabilities is not supported.
 *
 * @example
 * ```typescript
 * const capabilities = await getClientCapabilities();
 * if (capabilities?.immediateGet) {
 *   // Use immediate mediation
 * }
 * ```
 */
export async function getClientCapabilities(): Promise<WebAuthnClientCapabilities | null> {
  if (typeof PublicKeyCredential === "undefined") {
    return null;
  }

  if (!hasGetClientCapabilities(PublicKeyCredential)) {
    return null;
  }

  try {
    return await PublicKeyCredential.getClientCapabilities();
  } catch (error) {
    // SecurityError DOMException if RP domain is not valid
    console.error("Failed to get client capabilities:", error);
    return null;
  }
}

/**
 * Feature detection for WebAuthn mediation capabilities.
 * Simplified helper that checks both conditional and immediate mediation support.
 *
 * @returns Object with capability flags
 *
 * @example
 * ```typescript
 * const capabilities = await detectMediationCapabilities();
 * if (capabilities.conditional) {
 *   // Use conditional mediation for autofill
 *   authenticateWithFido2({ mediation: 'conditional' });
 * } else if (capabilities.immediate) {
 *   // Use immediate mediation for smart sign-in button
 *   try {
 *     await authenticateWithFido2({ mediation: 'immediate' }).signedIn;
 *   } catch (error) {
 *     // Library errors wrap the DOMException (error.name is never
 *     // 'NotAllowedError'); use the helper to detect this case
 *     if (isFido2NotAllowedError(error)) {
 *       showPasswordForm();
 *     }
 *   }
 * }
 * ```
 */
export async function detectMediationCapabilities(): Promise<{
  conditional: boolean;
  immediate: boolean;
}> {
  let conditional = false;
  let immediate = false;

  if (typeof PublicKeyCredential === "undefined") {
    return { conditional, immediate };
  }

  // Check conditional mediation support using legacy API
  if (
    typeof PublicKeyCredential.isConditionalMediationAvailable === "function"
  ) {
    try {
      conditional = await PublicKeyCredential.isConditionalMediationAvailable();
    } catch {
      // Ignore errors
    }
  }

  // Check immediate mediation support using new getClientCapabilities API
  const capabilities = await getClientCapabilities();
  if (capabilities) {
    // immediateGet is Chrome 139+ specific capability
    immediate = capabilities.immediateGet === true;

    // Fallback: conditionalGet also indicates conditional mediation support
    if (!conditional && capabilities.conditionalGet) {
      conditional = capabilities.conditionalGet;
    }
  }

  return { conditional, immediate };
}

export interface StoredCredential {
  credentialId: string;
  friendlyName: string;
  createdAt: Date;
  lastSignIn?: Date;
  signCount: number;
  transports?: AuthenticatorTransport[];
}

export interface ParsedFido2Assertion {
  credentialIdB64: string;
  authenticatorDataB64: string;
  clientDataJSON_B64: string;
  signatureB64: string;
  userHandleB64: string | null;
}

export interface PreparedFido2SignIn {
  username: string;
  /**
   * Cognito session for the CUSTOM_AUTH challenge. Note: Cognito invalidates
   * this session after `AuthSessionValidity` minutes (3 by default), so pass
   * the prepared bundle to authenticateWithFido2() promptly after it resolves.
   */
  session: string;
  credential: ParsedFido2Assertion;
  existingDeviceKey?: string;
}

/**
 * How long to let a conditional-mediation (autofill) credential request stay
 * pending on a single Cognito CUSTOM_AUTH session before renewing the session.
 *
 * Cognito invalidates a challenge session after `AuthSessionValidity` minutes
 * (3 by default, configurable 3-15), whereas a conditional
 * navigator.credentials.get() may stay pending indefinitely, until the user
 * picks an autofill suggestion. Renewing slightly below the minimum session
 * validity ensures the assertion is always signed over a challenge whose
 * Cognito session is still valid.
 */
export const COGNITO_AUTH_SESSION_RENEWAL_INTERVAL_MS = 150_000; // 2.5 minutes

/**
 * How many times to attempt the per-iteration `initiateFido2Challenge()` call
 * that refreshes the Cognito CUSTOM_AUTH session during a pending conditional
 * (autofill) request, before giving up and ending the flow.
 *
 * A conditional request can stay pending for a long time, so a single
 * transient network failure of the renewal initiate must not end passkey
 * autofill — the pending request could keep waiting. Retrying a bounded number
 * of times rides out brief blips; once the budget is exhausted the failure
 * propagates and ends the flow, as before.
 */
export const RENEWAL_INITIATE_MAX_ATTEMPTS = 3;

/**
 * Base backoff between retries of a failed renewal `initiateFido2Challenge()`.
 * Backoff grows linearly per attempt (1s, 2s, ...) and is capped by
 * {@link RENEWAL_INITIATE_BACKOFF_CAP_MS}. A supersede/abort during the backoff
 * ends the flow rather than waiting it out.
 */
export const RENEWAL_INITIATE_BACKOFF_BASE_MS = 1000;

/** Upper bound on the per-retry renewal-initiate backoff. */
export const RENEWAL_INITIATE_BACKOFF_CAP_MS = 4000;

type AuthenticatorAttestationResponseWithOptionalMembers =
  AuthenticatorAttestationResponse & {
    getTransports?: () => "" | string[];
    getAuthenticatorData?: () => unknown;
    getPublicKey?: () => unknown;
    getPublicKeyAlgorithm?: () => unknown;
  };

// Some environments/browsers/polyfills make instanceof checks unreliable for WebAuthn types
// (e.g., RHS missing a prototype). Use structural checks instead.
function isPublicKeyCredentialLike(o: unknown): o is PublicKeyCredential {
  return (
    !!o &&
    typeof o === "object" &&
    "type" in o &&
    o.type === "public-key" &&
    "rawId" in o &&
    "response" in o
  );
}

function isAuthenticatorAttestationResponseLike(
  o: unknown
): o is AuthenticatorAttestationResponseWithOptionalMembers {
  return (
    !!o &&
    typeof o === "object" &&
    "attestationObject" in (o as Record<string, unknown>) &&
    "clientDataJSON" in (o as Record<string, unknown>)
  );
}

function isAuthenticatorAssertionResponseLike(
  o: unknown
): o is AuthenticatorAssertionResponse {
  return (
    !!o &&
    typeof o === "object" &&
    "authenticatorData" in (o as Record<string, unknown>) &&
    "clientDataJSON" in (o as Record<string, unknown>) &&
    "signature" in (o as Record<string, unknown>)
  );
}

/**
 * Encode the server-provided user handle (user.id) as UTF-8 bytes.
 *
 * Sign-in decodes the userHandle returned by the authenticator with
 * TextDecoder (UTF-8), so registration must use the symmetric encoding —
 * otherwise non-ASCII usernames are corrupted at registration and
 * usernameless sign-in permanently fails for that credential.
 */
function encodeUserHandle(id: string) {
  const userHandle = new TextEncoder().encode(id);
  // WebAuthn caps user handles at 64 bytes — fail loudly instead of
  // letting the authenticator truncate or reject opaquely
  if (userHandle.byteLength > 64) {
    throw new Fido2ValidationError(
      `User handle must not exceed 64 bytes (got ${userHandle.byteLength} bytes)`,
      id
    );
  }
  return userHandle;
}

export async function fido2CreateCredential({
  friendlyName,
}: {
  friendlyName: string | (() => string | Promise<string>);
}) {
  const { debug, fido2 } = configure();
  const publicKeyOptions = await fido2StartCreateCredential();
  const publicKey: CredentialCreationOptions["publicKey"] = {
    ...publicKeyOptions,
    rp: {
      name: fido2?.rp?.name ?? publicKeyOptions.rp.name,
      id: fido2?.rp?.id ?? publicKeyOptions.rp.id,
    },
    attestation: fido2?.attestation,
    authenticatorSelection:
      publicKeyOptions.authenticatorSelection ?? fido2?.authenticatorSelection,
    extensions: fido2?.extensions,
    timeout: publicKeyOptions.timeout ?? fido2?.timeout,
    challenge: bufferFromBase64Url(publicKeyOptions.challenge),
    user: {
      ...publicKeyOptions.user,
      id: encodeUserHandle(publicKeyOptions.user.id),
    },
    excludeCredentials: publicKeyOptions.excludeCredentials.map(
      (credential) => ({
        ...credential,
        id: bufferFromBase64Url(credential.id),
      })
    ),
  };
  debug?.("Assembled public key options:", publicKey);
  let credential;
  try {
    credential = await navigator.credentials.create({
      publicKey,
    });
  } catch (err) {
    if (err instanceof DOMException) {
      throw fromDOMException(err);
    }
    throw err;
  }
  if (!credential) {
    throw new Fido2CredentialError("No credential returned from browser");
  }
  if (
    !isPublicKeyCredentialLike(credential) ||
    !isAuthenticatorAttestationResponseLike(credential.response)
  ) {
    throw new Fido2ValidationError(
      "Invalid credential response: expected AuthenticatorAttestationResponse",
      credential
    );
  }
  const response: AuthenticatorAttestationResponseWithOptionalMembers =
    credential.response;
  debug?.("Created credential:", {
    credential,
    getTransports: response.getTransports?.(),
    getAuthenticatorData: response.getAuthenticatorData?.(),
    getPublicKey: response.getPublicKey?.(),
    getPublicKeyAlgorithm: response.getPublicKeyAlgorithm?.(),
  });
  const resolvedFriendlyName =
    typeof friendlyName === "string" ? friendlyName : await friendlyName();
  return fido2CompleteCreateCredential({
    credential: credential,
    friendlyName: resolvedFriendlyName,
  });
}

interface StartCreateCredentialResponse {
  challenge: string;
  attestation: "none";
  rp: { name: string; id?: string };
  user: {
    id: string;
    name: string;
    displayName: string;
  };
  pubKeyCredParams: { type: "public-key"; alg: -7 | -257 }[];
  authenticatorSelection: { userVerification: UserVerificationRequirement };
  timeout: number;
  excludeCredentials: {
    id: string;
    type: "public-key";
  }[];
}

export interface ParsedCredential {
  clientDataJSON_B64: string;
  attestationObjectB64: string;
  transports?: string[]; // Should be: "usb" | "nfc" | "ble" | "internal" | "hybrid"
}

function getFullFido2Url(path: string) {
  const { fido2 } = configure();
  if (!fido2) {
    throw new Fido2ConfigError(
      "Fido2 configuration not initialized. Call configure() with fido2 options."
    );
  }
  return `${fido2.baseUrl.replace(/\/$/, "")}/${path.replace(/^\//, "")}`;
}

export async function fido2StartCreateCredential() {
  const { fido2, fetch, location } = configure();
  if (!fido2) {
    throw new Fido2ConfigError(
      "Fido2 configuration not initialized. Call configure() with fido2 options."
    );
  }
  const { idToken } = (await retrieveTokens()) ?? {};
  if (!idToken) {
    throw new Fido2AuthError(
      "No authentication token available. User must be signed in."
    );
  }
  return fetch(
    getFullFido2Url(
      `register-authenticator/start?rpId=${fido2.rp?.id ?? location.hostname}`
    ),
    {
      method: "POST",
      headers: {
        accept: "application/json, text/javascript",
        "content-type": "application/json; charset=UTF-8",
        authorization: `Bearer ${idToken}`,
      },
    }
  )
    .then(throwIfNot2xx)
    .then((res) => res.json() as Promise<StartCreateCredentialResponse>);
}

export async function fido2CompleteCreateCredential({
  credential,
  friendlyName,
}: {
  credential: PublicKeyCredential | ParsedCredential;
  friendlyName: string;
}) {
  const { fetch } = configure();
  const { idToken } = (await retrieveTokens()) ?? {};
  if (!idToken) {
    throw new Fido2AuthError(
      "No authentication token available. User must be signed in."
    );
  }
  const parsedCredential =
    "response" in credential
      ? await parseAuthenticatorAttestationResponse(
          credential.response as AuthenticatorAttestationResponseWithOptionalMembers
        )
      : credential;

  return fetch(getFullFido2Url("register-authenticator/complete"), {
    body: JSON.stringify({
      ...parsedCredential,
      friendlyName,
    }),
    method: "POST",
    headers: {
      accept: "application/json, text/javascript",
      "content-type": "application/json; charset=UTF-8",
      authorization: `Bearer ${idToken}`,
    },
  })
    .then(throwIfNot2xx)
    .then(
      (res) =>
        res.json() as Promise<{
          friendlyName: string;
          credentialId: string;
          createdAt: string;
          signCount: number;
        }>
    )
    .then(
      (res) =>
        ({
          ...res,
          createdAt: new Date(res.createdAt),
        }) as StoredCredential
    );
}

export async function fido2ListCredentials() {
  const { fido2, fetch, location } = configure();
  if (!fido2) {
    throw new Fido2ConfigError(
      "Fido2 configuration not initialized. Call configure() with fido2 options."
    );
  }
  const tokens = await retrieveTokens();
  if (!tokens?.idToken) {
    throw new Fido2AuthError(
      "No authentication token available. User must be signed in."
    );
  }
  return fetch(
    getFullFido2Url(
      `authenticators/list?rpId=${fido2.rp?.id ?? location.hostname}`
    ),
    {
      method: "POST",
      headers: {
        accept: "application/json, text/javascript",
        "content-type": "application/json; charset=UTF-8",
        authorization: `Bearer ${tokens.idToken}`,
      },
    }
  )
    .then(throwIfNot2xx)
    .then(
      (res) =>
        res.json() as Promise<{
          authenticators: {
            friendlyName: string;
            credentialId: string;
            createdAt: string;
            signCount: number;
            lastSignIn?: string;
          }[];
        }>
    )
    .then(({ authenticators }) => ({
      authenticators: authenticators.map((authenticator) => ({
        ...authenticator,
        createdAt: new Date(authenticator.createdAt),
        lastSignIn:
          authenticator.lastSignIn !== undefined
            ? new Date(authenticator.lastSignIn)
            : authenticator.lastSignIn,
      })),
    }));
}

export async function fido2DeleteCredential({
  credentialId,
}: {
  credentialId: string;
}) {
  const { fido2, fetch } = configure();
  if (!fido2) {
    throw new Fido2ConfigError(
      "Fido2 configuration not initialized. Call configure() with fido2 options."
    );
  }
  const tokens = await retrieveTokens();
  if (!tokens?.idToken) {
    throw new Fido2AuthError(
      "No authentication token available. User must be signed in."
    );
  }
  return fetch(getFullFido2Url("authenticators/delete"), {
    method: "POST",
    body: JSON.stringify({ credentialId }),
    headers: {
      accept: "application/json, text/javascript",
      "content-type": "application/json; charset=UTF-8",
      authorization: `Bearer ${tokens.idToken}`,
    },
  }).then(throwIfNot2xx);
}

export async function fido2UpdateCredential({
  credentialId,
  friendlyName,
}: {
  credentialId: string;
  friendlyName: string;
}) {
  const { fido2, fetch } = configure();
  if (!fido2) {
    throw new Fido2ConfigError(
      "Fido2 configuration not initialized. Call configure() with fido2 options."
    );
  }
  const tokens = await retrieveTokens();
  if (!tokens?.idToken) {
    throw new Fido2AuthError(
      "No authentication token available. User must be signed in."
    );
  }
  return fetch(getFullFido2Url("authenticators/update"), {
    method: "POST",
    body: JSON.stringify({ credentialId, friendlyName }),
    headers: {
      accept: "application/json, text/javascript",
      "content-type": "application/json; charset=UTF-8",
      authorization: `Bearer ${tokens.idToken}`,
    },
  }).then(throwIfNot2xx);
}

/**
 * The WebAuthn Signal API (https://w3c.github.io/webauthn/#sctn-signalMethods)
 * lets the relying party tell the browser/credential manager which credentials
 * it still accepts, so revoked or renamed passkeys stop being offered. These
 * static methods are recent and not yet in the TS DOM lib, so we type them here.
 */
interface SignalAllAcceptedCredentialsOptions {
  rpId: string;
  userId: string;
  allAcceptedCredentialIds: string[];
}

interface SignalUnknownCredentialOptions {
  rpId: string;
  credentialId: string;
}

interface SignalCurrentUserDetailsOptions {
  rpId: string;
  userId: string;
  name: string;
  displayName: string;
}

interface PublicKeyCredentialWithSignal {
  signalAllAcceptedCredentials(
    options: SignalAllAcceptedCredentialsOptions
  ): Promise<void>;
  signalUnknownCredential(
    options: SignalUnknownCredentialOptions
  ): Promise<void>;
  signalCurrentUserDetails(
    options: SignalCurrentUserDetailsOptions
  ): Promise<void>;
}

function getSignalRpId(rpId?: string): string {
  const { fido2, location } = configure();
  return rpId ?? fido2?.rp?.id ?? location.hostname;
}

/**
 * Encode a relying-party WebAuthn user handle to the base64url form the Signal
 * API expects. The caller passes the same handle the server used as `user.id`
 * in the start-registration response; we run it through the same encodeUserHandle
 * the library applies at registration so the value matches stored passkeys
 * byte-for-byte. We intentionally do not assume the handle equals the Cognito
 * `sub` — that only holds when the backend uses the raw sub as the handle.
 */
function encodeSignalUserId(userId: string): string {
  return bufferToBase64Url(encodeUserHandle(userId).buffer as ArrayBuffer);
}

/**
 * Signal the full set of credential IDs the relying party still accepts so the
 * browser/password manager drops revoked passkeys from autofill. Call after a
 * passkey is deleted (or on sign-in). No-op where the Signal API is unsupported.
 */
export async function signalAllAcceptedCredentials({
  allAcceptedCredentialIds,
  userId,
  rpId,
}: {
  allAcceptedCredentialIds: string[];
  /**
   * The relying party's WebAuthn user handle — the same value used as `user.id`
   * at registration. For Cognito backends that key passkeys by the raw `sub`,
   * pass the user's `sub`. Encoded internally so it matches stored passkeys.
   */
  userId: string;
  rpId?: string;
}): Promise<void> {
  const capabilities = await getClientCapabilities();
  if (!capabilities?.signalAllAcceptedCredentials) {
    return;
  }
  const pkc = PublicKeyCredential as typeof PublicKeyCredential &
    Partial<PublicKeyCredentialWithSignal>;
  if (typeof pkc.signalAllAcceptedCredentials !== "function") {
    return;
  }
  await pkc.signalAllAcceptedCredentials({
    rpId: getSignalRpId(rpId),
    userId: encodeSignalUserId(userId),
    allAcceptedCredentialIds,
  });
}

/**
 * Signal that a credential the relying party no longer recognizes should stop
 * being offered. Call when a sign-in is rejected for an unknown credential.
 * No-op where the Signal API is unsupported.
 */
export async function signalUnknownCredential({
  credentialId,
  rpId,
}: {
  credentialId: string;
  rpId?: string;
}): Promise<void> {
  const capabilities = await getClientCapabilities();
  if (!capabilities?.signalUnknownCredential) {
    return;
  }
  const pkc = PublicKeyCredential as typeof PublicKeyCredential &
    Partial<PublicKeyCredentialWithSignal>;
  if (typeof pkc.signalUnknownCredential !== "function") {
    return;
  }
  await pkc.signalUnknownCredential({
    rpId: getSignalRpId(rpId),
    credentialId,
  });
}

/**
 * Signal the user's current account name and display name so stored passkeys
 * show up-to-date details. No-op where the Signal API is unsupported.
 */
export async function signalCurrentUserDetails({
  name,
  displayName,
  userId,
  rpId,
}: {
  name: string;
  displayName: string;
  /**
   * The relying party's WebAuthn user handle — the same value used as `user.id`
   * at registration. For Cognito backends that key passkeys by the raw `sub`,
   * pass the user's `sub`. Encoded internally so it matches stored passkeys.
   */
  userId: string;
  rpId?: string;
}): Promise<void> {
  const capabilities = await getClientCapabilities();
  if (!capabilities?.signalCurrentUserDetails) {
    return;
  }
  const pkc = PublicKeyCredential as typeof PublicKeyCredential &
    Partial<PublicKeyCredentialWithSignal>;
  if (typeof pkc.signalCurrentUserDetails !== "function") {
    return;
  }
  await pkc.signalCurrentUserDetails({
    rpId: getSignalRpId(rpId),
    userId: encodeSignalUserId(userId),
    name,
    displayName,
  });
}

interface Fido2Options {
  challenge: string;
  timeout?: number;
  userVerification?: UserVerificationRequirement;
  relyingPartyId?: string;
  credentials?: { id: string; transports?: AuthenticatorTransport[] }[];
  signal?: AbortSignal;
  mediation?: MediationMode;
}

function assertIsFido2Options(o: unknown): asserts o is Fido2Options {
  // Basic object check
  if (!o || typeof o !== "object") {
    throw new Fido2ValidationError("Fido2 options must be an object", o);
  }

  // Required: challenge
  if (
    !("challenge" in o) ||
    typeof o.challenge !== "string" ||
    !o.challenge.length
  ) {
    throw new Fido2ValidationError(
      "Fido2 options must have a non-empty challenge string",
      o
    );
  }

  // Optional: relyingPartyId
  if ("relyingPartyId" in o && typeof o.relyingPartyId !== "string") {
    throw new Fido2ValidationError("relyingPartyId must be a string", o);
  }

  // Optional: timeout
  if ("timeout" in o && typeof o.timeout !== "number") {
    throw new Fido2ValidationError("timeout must be a number", o);
  }

  // Optional: userVerification
  if ("userVerification" in o && typeof o.userVerification !== "string") {
    throw new Fido2ValidationError("userVerification must be a string", o);
  }

  // Optional: credentials
  if ("credentials" in o) {
    if (!Array.isArray(o.credentials)) {
      throw new Fido2ValidationError("credentials must be an array", o);
    }

    for (const credential of o.credentials) {
      if (!credential || typeof credential !== "object") {
        throw new Fido2ValidationError("Each credential must be an object", o);
      }

      const cred = credential as Record<string, unknown>;

      if (!("id" in cred) || typeof cred.id !== "string" || !cred.id.length) {
        throw new Fido2ValidationError(
          "Each credential must have a non-empty id string",
          o
        );
      }

      if ("transports" in cred) {
        if (!Array.isArray(cred.transports)) {
          throw new Fido2ValidationError(
            "credential.transports must be an array",
            o
          );
        }

        for (const transport of cred.transports) {
          if (typeof transport !== "string") {
            throw new Fido2ValidationError(
              "Each transport must be a string",
              o
            );
          }
        }
      }
    }
  }
}

/**
 * Tracks the currently pending conditional (autofill) credentials.get() request.
 *
 * Per the Credential Management API, only one credentials.get() request may be
 * pending at a time. Without coordination, a deliberate modal request (e.g. the
 * user clicking "sign in with passkey" while the conditional autofill request
 * started at page load is still pending) is rejected by the browser (Chrome:
 * "A request is already pending") while the invisible conditional request keeps
 * pending. The standard pattern is to abort the pending conditional request via
 * AbortController before starting a new request.
 */
let pendingConditionalGet:
  | {
      controller: AbortController;
      settled: Promise<void>;
      /**
       * Set when a newer credential request aborts this conditional request
       * to take over, so the resulting abort can be told apart from a
       * cancellation by the caller's own abort signal.
       */
      superseded: boolean;
    }
  | undefined = undefined;

/**
 * A conditional (autofill) sign-in flow, tracked for its ENTIRE lifetime —
 * including the gaps between renewal iterations, when the previous
 * navigator.credentials.get() has been aborted and the next one has not yet
 * been issued (e.g. while initiating a fresh Cognito challenge). A modal
 * takeover marks `superseded` here even when no get() is pending, so the
 * renewal loop stops re-arming instead of running invisibly behind the modal
 * sign-in forever. `pendingConditionalGet` only covers the narrower window
 * while a get() is actually pending.
 */
type ActiveConditionalFlow = {
  superseded: boolean;
  /**
   * Aborted in lockstep with `superseded` (see {@link supersedeConditionalFlow})
   * so code blocked on an AbortSignal between renewal iterations — the
   * initiate-retry backoff — wakes immediately on a takeover instead of waiting
   * out the full backoff. A modal takeover marks the flow superseded but does
   * NOT abort the caller's own signal, so the boolean alone is invisible to
   * anything sleeping on a signal.
   */
  supersededAbort: AbortController;
};

let activeConditionalFlow: ActiveConditionalFlow | undefined = undefined;

/**
 * Supersede a conditional flow: mark it AND wake anything waiting on it. The
 * `superseded` boolean is polled at renewal-loop boundaries, but the
 * initiate-retry backoff blocks on an AbortSignal — and a takeover never aborts
 * the caller's signal — so without this the backoff is waited out in full (up
 * to {@link RENEWAL_INITIATE_BACKOFF_CAP_MS}) before the flow notices.
 */
function supersedeConditionalFlow(flow: ActiveConditionalFlow): void {
  flow.superseded = true;
  flow.supersededAbort.abort();
}

/**
 * Serializes the issuance of navigator.credentials.get() requests.
 *
 * Concurrent fido2getCredential calls must not issue overlapping
 * credentials.get() requests: the browser rejects all but the first.
 * Modal (and immediate/default mediation) requests hold the lock until their
 * request settles. Conditional (autofill) requests are long-lived, so they
 * release the lock as soon as their request is issued: a later request takes
 * the lock and aborts them via pendingConditionalGet instead of queueing
 * behind them.
 */
let credentialsGetLock: Promise<void> = Promise.resolve();

/**
 * How long a new credential request waits for an aborted (superseded)
 * conditional credentials.get() request to settle before proceeding anyway.
 *
 * Conforming browsers settle an aborted request promptly, but a
 * non-conforming browser or extension-wrapped navigator.credentials.get may
 * ignore the AbortController and never settle. Since this wait happens while
 * holding the credentials.get() lock, an unbounded wait would hang all
 * future passkey requests.
 */
export const SUPERSEDED_SETTLEMENT_TIMEOUT_MS = 3000;

async function acquireCredentialsGetLock(): Promise<() => void> {
  const previous = credentialsGetLock;
  let release!: () => void;
  credentialsGetLock = new Promise<void>((resolve) => (release = resolve));
  await previous;
  return release;
}

export async function fido2getCredential({
  relyingPartyId,
  challenge,
  credentials,
  timeout,
  userVerification,
  signal,
  mediation,
}: Fido2Options): Promise<ParsedFido2Assertion> {
  const { debug, fido2: { extensions } = {} } = configure();

  debug?.("🔐 fido2getCredential called", {
    mediation,
    hasSignal: !!signal,
    signalAborted: signal?.aborted,
    timeout,
    userVerification,
    credentialsCount: credentials?.length ?? 0,
  });

  // Runtime validation and parameter adjustments based on mediation mode
  if (mediation === "conditional") {
    // Conditional mediation: autofill UI for password managers
    if (typeof PublicKeyCredential === "undefined") {
      throw new Fido2ConfigError(
        "Conditional mediation requested but PublicKeyCredential is not available. " +
          "This browser may not support WebAuthn."
      );
    }
    if (
      typeof PublicKeyCredential.isConditionalMediationAvailable === "function"
    ) {
      let isAvailable: boolean | undefined;
      try {
        isAvailable =
          await PublicKeyCredential.isConditionalMediationAvailable();
      } catch (error) {
        debug?.(
          "⚠️ Cannot verify conditional mediation support - proceeding with conditional mediation anyway",
          error
        );
      }
      if (isAvailable === false) {
        throw new Fido2ConfigError(
          "Conditional mediation requested but not supported by this browser."
        );
      }
    } else {
      debug?.(
        "⚠️ Cannot verify conditional mediation support - PublicKeyCredential.isConditionalMediationAvailable() not available"
      );
    }
  } else if (mediation === "immediate") {
    // Immediate mediation: frictionless sign-in with instant fallback
    if (typeof PublicKeyCredential === "undefined") {
      throw new Fido2ConfigError(
        "Immediate mediation requested but PublicKeyCredential is not available. " +
          "This browser may not support WebAuthn."
      );
    }
    // Note: Feature detection via getClientCapabilities().immediateGet should be done by caller
    debug?.(
      "Using immediate mediation - will fail fast with NotAllowedError if no local credentials"
    );
  }

  // Adjust parameters based on mediation mode
  let effectiveUserVerification = userVerification;
  let effectiveTimeout = timeout;

  if (mediation === "conditional") {
    // Conditional mediation: default userVerification to "preferred" (per passkeys.dev
    // UX guidance) only when nothing was requested. A requested value (e.g. "required"
    // from the server's fido2options) is passed through unchanged, so the authenticator
    // performs user verification when the backend will verify the UV flag.
    if (!userVerification) {
      effectiveUserVerification = "preferred";
      debug?.(
        `userVerification not specified - defaulting to "preferred" for conditional mediation`
      );
    }
    effectiveTimeout = undefined;

    if (timeout) {
      debug?.(
        `⚠️ WebAuthn spec recommends removing timeout for conditional mediation. ` +
          `Overriding timeout ${timeout}ms → undefined (browser default)`
      );
    }
  }
  // Immediate mediation uses parameters as-is (no overrides needed)

  const publicKey: CredentialRequestOptions["publicKey"] = {
    challenge: bufferFromBase64Url(challenge),
    allowCredentials: credentials?.map((credential) => ({
      id: bufferFromBase64Url(credential.id),
      transports: credential.transports,
      type: "public-key" as const,
    })),
    timeout: effectiveTimeout,
    userVerification: effectiveUserVerification,
    rpId: relyingPartyId,
    extensions,
  };
  debug?.("Assembled public key options:", publicKey);

  // Only one credentials.get() request may be pending at a time. Take the
  // lock so concurrent fido2getCredential calls cannot issue overlapping
  // requests (a pending modal request holds the lock until it settles)
  const releaseLock = await acquireCredentialsGetLock();
  let credential;
  try {
    // A non-conditional (modal / immediate / default) request taking the lock
    // is a takeover of any active conditional autofill flow: mark that flow
    // superseded so its renewal loop stops re-arming — even if this lands in
    // the renewal gap where no get() is pending (so pendingConditionalGet is
    // momentarily undefined). The flow's own conditional renewal re-arm is
    // mediation === "conditional" and must NOT self-supersede here.
    if (mediation !== "conditional" && activeConditionalFlow) {
      supersedeConditionalFlow(activeConditionalFlow);
    }

    // If a conditional (autofill) request is still pending, abort it first so
    // the browser accepts this new request instead of rejecting it
    if (pendingConditionalGet) {
      debug?.(
        "⚠️ Aborting pending conditional (autofill) credentials.get() so the new credential request can proceed"
      );
      const aborted = pendingConditionalGet;
      aborted.superseded = true;
      aborted.controller.abort();
      // Wait for the aborted request to settle before issuing the new
      // request (the tracker is cleared upon settlement). Bound the wait:
      // a non-conforming credentials.get may ignore the abort and never
      // settle, and we hold the lock here - waiting forever would hang all
      // future credential requests
      let settlementTimer: ReturnType<typeof setTimeout> | undefined;
      const timedOut = await Promise.race([
        aborted.settled.then(() => false),
        new Promise<boolean>(
          (resolve) =>
            (settlementTimer = setTimeout(
              () => resolve(true),
              SUPERSEDED_SETTLEMENT_TIMEOUT_MS
            ))
        ),
      ]);
      clearTimeout(settlementTimer);
      if (timedOut) {
        debug?.(
          `⚠️ Aborted conditional credentials.get() did not settle within ${SUPERSEDED_SETTLEMENT_TIMEOUT_MS}ms - proceeding with the new request anyway`
        );
        // Clear the stale tracker so it cannot wedge subsequent requests.
        // If the old request ever settles, its settlement handler only
        // clears the tracker if it still points at itself (identity check),
        // so it cannot corrupt the state of a newer conditional request
        if (pendingConditionalGet === aborted) {
          pendingConditionalGet = undefined;
        }
      }
    }

    // For conditional requests, use an internal AbortController (chained to
    // the caller's signal, if any) so a subsequent modal request can abort us
    let effectiveSignal = signal;
    let conditionalAbort: AbortController | undefined = undefined;
    if (mediation === "conditional") {
      const controller = new AbortController();
      if (signal?.aborted) {
        controller.abort();
      } else {
        signal?.addEventListener("abort", () => controller.abort(), {
          once: true,
        });
      }
      conditionalAbort = controller;
      effectiveSignal = controller.signal;
    }

    debug?.("🚀 Calling navigator.credentials.get()", {
      mediation,
      hasSignal: !!signal,
      signalAborted: signal?.aborted,
      effectiveTimeout,
      effectiveUserVerification,
    });

    let conditionalTracker: typeof pendingConditionalGet = undefined;
    try {
      // Type assertion needed: 'immediate' mediation not yet in TS lib definitions (CredentialMediationRequirement)
      // Runtime support: Chrome 139+, see https://developer.chrome.com/blog/webauthn-immediate-mediation
      const getCredential = navigator.credentials.get({
        publicKey,
        signal: effectiveSignal,
        mediation: mediation as CredentialMediationRequirement,
      });
      if (conditionalAbort) {
        // Track this conditional request at module level, and clear the
        // tracker once it settles (for any reason)
        const tracker = {
          controller: conditionalAbort,
          settled: getCredential.then(
            () => undefined,
            () => undefined
          ),
          superseded: false,
        };
        conditionalTracker = tracker;
        pendingConditionalGet = tracker;
        void tracker.settled.then(() => {
          if (pendingConditionalGet === tracker) {
            pendingConditionalGet = undefined;
          }
        });
        // Conditional requests are long-lived: release the lock as soon as
        // the request is issued, so a later request can take the lock and
        // abort us instead of queueing behind us (which would deadlock)
        releaseLock();
      }
      credential = await getCredential;
      debug?.("✅ navigator.credentials.get() succeeded");
    } catch (err) {
      if (err instanceof DOMException) {
        debug?.("❌ credentials.get() threw DOMException", {
          name: err.name,
          message: err.message,
          wasSignalAborted: signal?.aborted,
          mediation,
        });
        if (
          err.name === "AbortError" &&
          conditionalTracker?.superseded &&
          !signal?.aborted
        ) {
          // Aborted by a newer credential request taking over - not by the
          // caller's own abort signal
          throw new Fido2AbortError(
            "WebAuthn operation was aborted: superseded by a newer credential request",
            "Passkey verification was cancelled",
            { superseded: true }
          );
        }
        throw fromDOMException(err);
      }
      debug?.("❌ credentials.get() threw non-DOMException error", {
        error: err,
      });
      throw err;
    }
  } finally {
    // No-op if the lock was already released (a promise only resolves once)
    releaseLock();
  }
  if (!credential) {
    throw new Fido2CredentialError("No credential returned from browser");
  }
  if (
    !isPublicKeyCredentialLike(credential) ||
    !isAuthenticatorAssertionResponseLike(credential.response)
  ) {
    throw new Fido2ValidationError(
      "Invalid credential response: expected AuthenticatorAssertionResponse",
      credential
    );
  }
  debug?.("✅ Credential received and validated:", credential);
  return parseAuthenticatorAssertionResponse(
    credential.rawId,
    credential.response
  );
}

const parseAuthenticatorAttestationResponse = async (
  response: AuthenticatorAttestationResponseWithOptionalMembers
) => {
  const [attestationObjectB64, clientDataJSON_B64] = await Promise.all([
    bufferToBase64Url(response.attestationObject),
    bufferToBase64Url(response.clientDataJSON),
  ]);
  const transports = (response.getTransports?.() || []).filter((transport) =>
    ["ble", "hybrid", "internal", "nfc", "usb"].includes(transport)
  );
  return {
    attestationObjectB64,
    clientDataJSON_B64,
    transports: transports.length ? transports : undefined,
  };
};

const parseAuthenticatorAssertionResponse = async (
  rawId: ArrayBuffer,
  response: AuthenticatorAssertionResponse
) => {
  const [
    credentialIdB64,
    authenticatorDataB64,
    clientDataJSON_B64,
    signatureB64,
    userHandleB64,
  ] = await Promise.all([
    bufferToBase64Url(rawId),
    bufferToBase64Url(response.authenticatorData),
    bufferToBase64Url(response.clientDataJSON),
    bufferToBase64Url(response.signature),
    response.userHandle && response.userHandle.byteLength > 0
      ? bufferToBase64Url(response.userHandle)
      : null,
  ]);
  return {
    credentialIdB64,
    authenticatorDataB64,
    clientDataJSON_B64,
    signatureB64,
    userHandleB64,
  };
};

async function requestUsernamelessSignInChallenge() {
  const { fido2, fetch } = configure();
  if (!fido2) {
    throw new Fido2ConfigError(
      "Fido2 configuration not initialized. Call configure() with fido2 options."
    );
  }
  return fetch(getFullFido2Url("sign-in-challenge"), {
    method: "POST",
    headers: {
      accept: "application/json, text/javascript",
    },
  })
    .then(throwIfNot2xx)
    .then((res) => res.json() as unknown);
}

/**
 * Prepares a FIDO2 sign-in by obtaining WebAuthn credentials and Cognito session.
 * Can be called early (e.g., page load) and the result passed to authenticateWithFido2 later.
 *
 * **Performance Tip**: For conditional mediation (autofill), always provide the username if available:
 * - ✅ WITH username: Challenge created upfront → fast, correct flow
 * - ⚠️ WITHOUT username: Credential first → extract username → get session → slower, requires backend coordination
 *
 * Password managers typically store usernames, so username-based flow is recommended.
 *
 * **Session validity**: Cognito invalidates a challenge session after
 * `AuthSessionValidity` minutes (3 by default). For the username-based flow with
 * conditional mediation, this function transparently renews the session (and its
 * FIDO2 challenge) while the autofill request is pending, so users can pick a
 * passkey from autofill long after page load. Once the returned promise resolves
 * though, the contained session is subject to expiry: pass the prepared bundle
 * to authenticateWithFido2() promptly.
 *
 * @example
 * ```typescript
 * // ✅ Recommended: Fast path with username
 * const prepared = await prepareFido2SignIn({
 *   username: 'alice@example.com',
 *   mediation: 'conditional'
 * });
 *
 * // ⚠️ Slower: Usernameless (only use when username truly unknown)
 * const prepared = await prepareFido2SignIn({
 *   mediation: 'conditional'
 * });
 * ```
 */
export async function prepareFido2SignIn({
  username,
  credentials,
  credentialGetter = fido2getCredential,
  mediation,
  signal,
}: {
  /** Username or alias. Providing this enables the FAST username-based flow. */
  username?: string;
  credentials?: { id: string; transports?: AuthenticatorTransport[] }[];
  credentialGetter?: typeof fido2getCredential;
  mediation?: MediationMode;
  signal?: AbortSignal;
}): Promise<PreparedFido2SignIn> {
  const { debug, fido2 } = configure();
  if (!fido2) {
    throw new Fido2ConfigError(
      "Fido2 configuration not initialized. Call configure() with fido2 options."
    );
  }

  debug?.("🔓 prepareFido2SignIn called", {
    hasUsername: !!username,
    username: username ? `${username.substring(0, 3)}***` : undefined,
    mediation,
    hasSignal: !!signal,
    signalAborted: signal?.aborted,
    credentialsCount: credentials?.length ?? 0,
  });

  // Monitor abort signal
  if (signal) {
    const abortHandler = () => {
      debug?.("⚠️ prepareFido2SignIn: abort signal fired", {
        hasUsername: !!username,
        mediation,
      });
    };
    signal.addEventListener("abort", abortHandler, { once: true });
  }

  let resolvedUsername = username;
  let existingDeviceKey: string | undefined;
  let session: string | undefined;
  let assertion: ParsedFido2Assertion;

  // ✅ Flow 1: Username provided - Use fast username-based passkey flow
  // This is MUCH faster for conditional mediation when password manager knows the username
  // Challenge is created upfront → credential signed with correct challenge → no second initiateAuth needed
  if (resolvedUsername) {
    debug?.("🔐 Username-based passkey flow (FAST PATH)", {
      username: resolvedUsername,
      mediation,
    });

    const usernameForAuth = resolvedUsername;
    existingDeviceKey = await retrieveDeviceKey(resolvedUsername);
    const deviceKeyForAuth = existingDeviceKey;

    const initiateFido2Challenge = async () => {
      const initAuthResponse = await initiateAuth({
        authflow: "CUSTOM_AUTH",
        authParameters: {
          USERNAME: usernameForAuth,
          ...(deviceKeyForAuth ? { DEVICE_KEY: deviceKeyForAuth } : {}),
        },
        abort: signal,
      });

      assertIsChallengeResponse(initAuthResponse);
      if (!initAuthResponse.ChallengeParameters.fido2options) {
        throw new Error("Server did not send a FIDO2 challenge");
      }

      const fido2options: unknown = JSON.parse(
        initAuthResponse.ChallengeParameters.fido2options
      );
      assertIsFido2Options(fido2options);
      debug?.("FIDO2 challenge received from Cognito");
      return { fido2options, session: initAuthResponse.Session };
    };

    const getCredentialForChallenge = (
      fido2options: Fido2Options,
      credentialSignal?: AbortSignal
    ) =>
      credentialGetter({
        ...fido2options,
        relyingPartyId: fido2.rp?.id ?? fido2options.relyingPartyId,
        timeout: fido2.timeout ?? fido2options.timeout,
        userVerification:
          fido2.authenticatorSelection?.userVerification ??
          fido2options.userVerification,
        credentials: (fido2options.credentials ?? []).concat(
          credentials?.filter(
            (cred) =>
              !fido2options.credentials?.find(
                (optionsCred) => cred.id === optionsCred.id
              )
          ) ?? []
        ),
        mediation,
        signal: credentialSignal,
      });

    if (mediation === "conditional") {
      // Conditional mediation is "set and forget": the pending
      // navigator.credentials.get() only resolves when the user eventually
      // picks an autofill suggestion, which can easily take longer than the
      // Cognito auth session stays valid (AuthSessionValidity, 3 minutes by
      // default). Proactively renew the session (and the FIDO2 challenge that
      // comes with it) before it expires, by aborting the pending conditional
      // request and restarting it with the fresh challenge. Pending
      // conditional requests show no UI, so renewal is invisible to the user.
      const RENEW_SESSION = Symbol("renew-session");
      const SETTLE_TIMEOUT = Symbol("settle-timeout");

      // Mark this conditional flow active for its whole lifetime so a modal
      // takeover can stop it even during the renewal gap (no get() pending).
      const flow: ActiveConditionalFlow = {
        superseded: false,
        supersededAbort: new AbortController(),
      };
      const previousFlow = activeConditionalFlow;
      // A newer conditional flow taking over supersedes any still-active older
      // one, so an older flow paused in its initiate-retry backoff ends promptly
      // instead of waking later to re-arm and abort this newer flow's get(). A
      // pending older get() is already aborted via pendingConditionalGet; this
      // covers the renewal gap, where none is pending and the takeover path's
      // `mediation !== "conditional"` guard would otherwise skip it.
      if (previousFlow) supersedeConditionalFlow(previousFlow);
      activeConditionalFlow = flow;

      // Throw the abort that ends the flow: superseded by a takeover, or a
      // plain cancellation by the caller's own signal.
      const abortFlow = (): never => {
        if (flow.superseded) {
          throw new Fido2AbortError(
            "WebAuthn operation was aborted: superseded by a newer credential request",
            "Passkey verification was cancelled",
            { superseded: true }
          );
        }
        throw new Fido2AbortError();
      };

      // Backoff that wakes promptly on either a caller abort OR a takeover
      // (which marks flow.superseded and aborts flow.supersededAbort but never
      // the caller's signal), so a supersede/abort during the wait ends the
      // flow immediately instead of being waited out for the full backoff.
      const backoffSleep = (ms: number) =>
        new Promise<void>((resolve) => {
          const supersededSignal = flow.supersededAbort.signal;
          if (signal?.aborted || supersededSignal.aborted) {
            resolve();
            return;
          }
          const done = () => {
            clearTimeout(timer);
            signal?.removeEventListener("abort", done);
            supersededSignal.removeEventListener("abort", done);
            resolve();
          };
          const timer = setTimeout(done, ms);
          signal?.addEventListener("abort", done, { once: true });
          supersededSignal.addEventListener("abort", done, { once: true });
        });

      // Refresh the Cognito CUSTOM_AUTH challenge for a renewal iteration,
      // riding out transient failures of initiateFido2Challenge(): a single
      // network blip must not end an otherwise-pending autofill request. A
      // supersede/abort is never retried — it ends the flow promptly.
      const initiateRenewalChallenge = async () => {
        for (let attempt = 1; ; attempt++) {
          // A takeover/abort that landed before (or while) initiating must end
          // the flow, not be swallowed as a transient failure and retried.
          if (flow.superseded || signal?.aborted) abortFlow();
          try {
            return await initiateFido2Challenge();
          } catch (err) {
            // Supersede/abort wins over any retry: end the flow now.
            if (flow.superseded || signal?.aborted) abortFlow();
            if (attempt >= RENEWAL_INITIATE_MAX_ATTEMPTS) {
              // Budget exhausted: propagate, ending the flow as before.
              throw err;
            }
            const backoff = Math.min(
              RENEWAL_INITIATE_BACKOFF_BASE_MS * attempt,
              RENEWAL_INITIATE_BACKOFF_CAP_MS
            );
            debug?.(
              `⚠️ Renewal initiateFido2Challenge() failed (attempt ${attempt}/${RENEWAL_INITIATE_MAX_ATTEMPTS}) - retrying in ${backoff}ms`
            );
            await backoffSleep(backoff);
          }
        }
      };

      try {
        for (;;) {
          // A modal takeover may have superseded this flow during the previous
          // iteration's renewal gap, including while awaiting initiate below.
          if (flow.superseded || signal?.aborted) abortFlow();

          const challenge = await initiateRenewalChallenge();

          // Re-check: a takeover could have landed during the (awaited)
          // initiate call — exactly the window pendingConditionalGet misses.
          if (flow.superseded || signal?.aborted) abortFlow();

          const renewalAbort = new AbortController();
          const forwardAbort = () => renewalAbort.abort();
          if (signal?.aborted) {
            renewalAbort.abort();
          } else {
            signal?.addEventListener("abort", forwardAbort, { once: true });
          }
          let renewalTimer: ReturnType<typeof setTimeout> | undefined;
          const credentialPromise = getCredentialForChallenge(
            challenge.fido2options,
            renewalAbort.signal
          );
          try {
            const raceOutcome = await Promise.race([
              credentialPromise,
              new Promise<typeof RENEW_SESSION>((resolve) => {
                renewalTimer = setTimeout(
                  () => resolve(RENEW_SESSION),
                  COGNITO_AUTH_SESSION_RENEWAL_INTERVAL_MS
                );
              }),
            ]);
            if (raceOutcome !== RENEW_SESSION) {
              // A modal takeover may have set flow.superseded in the same
              // tick the credential resolved (or for an injected getter the
              // takeover's abort never reached it): a superseded flow must
              // not complete with an assertion — the modal flow owns the
              // sign-in now.
              if (flow.superseded) abortFlow();
              assertion = raceOutcome;
              session = challenge.session;
              break;
            }
            debug?.(
              "🔄 Cognito auth session nearing expiry while conditional request pending - renewing challenge"
            );
            renewalAbort.abort();
            // A takeover that landed during this iteration ends the flow.
            if (flow.superseded) abortFlow();
            let settleTimer: ReturnType<typeof setTimeout> | undefined;
            try {
              // The user may have picked a credential just as the renewal
              // timer fired - if so, the current session is still valid, use
              // it. Bound the wait: a non-conforming get() may ignore the
              // abort and never settle, and the renewal loop must not hang.
              const settled = await Promise.race([
                credentialPromise,
                new Promise<typeof SETTLE_TIMEOUT>((resolve) => {
                  settleTimer = setTimeout(
                    () => resolve(SETTLE_TIMEOUT),
                    SUPERSEDED_SETTLEMENT_TIMEOUT_MS
                  );
                }),
              ]);
              if (settled === SETTLE_TIMEOUT) {
                debug?.(
                  `⚠️ Aborted conditional get() did not settle within ${SUPERSEDED_SETTLEMENT_TIMEOUT_MS}ms during renewal - re-arming with a fresh challenge`
                );
                continue;
              }
              // As above: a takeover during the settle wait wins over a
              // late-resolving credential.
              if (flow.superseded) abortFlow();
              assertion = settled;
              session = challenge.session;
              break;
            } catch (err) {
              // A takeover wins over a plain renewal abort regardless of how
              // the per-get classifier labelled this error (the same-tick
              // renewal-abort + supersede race can mislabel it).
              if (flow.superseded) abortFlow();
              if (
                !isFido2AbortError(err) ||
                signal?.aborted ||
                err.superseded
              ) {
                // Not our renewal abort: rethrow. A superseded abort means a
                // newer credential request took over — end here rather than
                // restart behind it.
                throw err;
              }
              // Aborted by us for renewal - loop around for a fresh challenge
            } finally {
              clearTimeout(settleTimer);
            }
          } finally {
            clearTimeout(renewalTimer);
            signal?.removeEventListener("abort", forwardAbort);
          }
        }
      } finally {
        if (activeConditionalFlow === flow) {
          // This flow superseded previousFlow at setup, so by here previousFlow
          // is dead; restoring it would leave activeConditionalFlow pointing at
          // a superseded flow instead of "no live conditional flow". Restore
          // only a still-live previous flow, else clear to undefined.
          activeConditionalFlow =
            previousFlow && !previousFlow.superseded ? previousFlow : undefined;
        }
      }
    } else {
      const challenge = await initiateFido2Challenge();
      assertion = await getCredentialForChallenge(
        challenge.fido2options,
        signal
      );
      session = challenge.session;
    }
  }
  // ⚠️ Flow 2: Usernameless - SLOWER but works when username unknown
  // Only use this when password manager doesn't have username stored
  // credential first → extract username → get session (requires backend coordination)
  else {
    debug?.("🌐 Usernameless passkey flow (SLOW PATH - no username available)");

    const fido2options = await requestUsernamelessSignInChallenge();
    assertIsFido2Options(fido2options);
    debug?.("Usernameless challenge received");

    assertion = await credentialGetter({
      ...fido2options,
      relyingPartyId: fido2.rp?.id ?? fido2options.relyingPartyId,
      timeout: fido2.timeout ?? fido2options.timeout,
      userVerification:
        fido2.authenticatorSelection?.userVerification ??
        fido2options.userVerification,
      // Merge server credentials with client-provided credentials (same as username flow)
      credentials: (fido2options.credentials ?? []).concat(
        credentials?.filter(
          (cred) =>
            !fido2options.credentials?.find(
              (optionsCred) => cred.id === optionsCred.id
            )
        ) ?? []
      ),
      mediation,
      signal,
    });

    if (!assertion.userHandleB64) {
      throw new Error("No discoverable credentials available");
    }

    let decodedUsername = new TextDecoder().decode(
      bufferFromBase64Url(assertion.userHandleB64)
    );

    if (decodedUsername.startsWith("s|")) {
      debug?.(
        "Credential userHandle isn't a username. In order to use the username as userHandle, so users can sign in without typing their username, usernames must be opaque"
      );
      throw new Error("Username is required for initiating sign-in");
    }

    decodedUsername = decodedUsername.replace(/^u\|/, "");
    if (!decodedUsername) {
      throw new Error("Invalid userHandle: username cannot be empty");
    }

    resolvedUsername = decodedUsername;
    debug?.(`✅ Username discovered: ${resolvedUsername}`);

    // Now get the Cognito session for this username
    existingDeviceKey = await retrieveDeviceKey(resolvedUsername);
    const initAuthResponse = await initiateAuth({
      authflow: "CUSTOM_AUTH",
      authParameters: {
        USERNAME: resolvedUsername,
        ...(existingDeviceKey ? { DEVICE_KEY: existingDeviceKey } : {}),
      },
      abort: signal,
    });

    assertIsChallengeResponse(initAuthResponse);
    session = initAuthResponse.Session;
  }

  if (!session) {
    throw new Fido2AuthError("Failed to obtain Cognito session");
  }

  debug?.("✅ FIDO2 sign-in prepared", {
    username: resolvedUsername,
    hasDeviceKey: !!existingDeviceKey,
  });

  return {
    username: resolvedUsername,
    credential: assertion,
    session,
    existingDeviceKey,
  };
}

export function authenticateWithFido2({
  username,
  credentials,
  tokensCb,
  statusCb,
  currentStatus,
  clientMetadata,
  credentialGetter = fido2getCredential,
  mediation,
  prepared,
}: {
  /**
   * Username, or alias (e-mail, phone number)
   * If not specified, sign in with FIDO2 Passkey (discoverable credential) will be attempted
   */
  username?: string;
  /**
   * The FIDO2 credentials to use.
   * Must be specified for non-discoverable credentials to work, optional for Passkeys (discoverable credentials).
   * Ignored if username is not specified, to force the user agent to look for Passkeys (discoverable credentials).
   */
  credentials?: { id: string; transports?: AuthenticatorTransport[] }[];
  tokensCb?: (tokens: TokensFromSignIn) => void | Promise<void>;
  statusCb?: (status: BusyState | IdleState) => void;
  currentStatus?: BusyState | IdleState;
  clientMetadata?: Record<string, string>;
  credentialGetter?: typeof fido2getCredential;
  /**
   * WebAuthn mediation mode for controlling authentication flow.
   *
   * **'conditional'** - Autofill UI (Password Manager Integration):
   * - Passkeys appear in browser autofill suggestions
   * - "Set and forget" - only resolves if user selects from autofill
   * - userVerification defaults to "preferred" when not specified
   * - timeout removed (per WebAuthn spec)
   * - Requires: HTML input with autocomplete="username webauthn"
   *
   * **'immediate'** - Frictionless Sign-In Button:
   * - Shows credential picker if local credentials exist
   * - Fails fast with NotAllowedError if no local credentials
   * - Enables intelligent fallback to password forms
   * - No cross-device/QR code prompts
   * - Requires: User gesture (button click)
   *
   * Usage patterns:
   * ```typescript
   * import { detectMediationCapabilities, getClientCapabilities } from './fido2';
   * import { isFido2NotAllowedError } from './errors';
   *
   * // Option 1: Simple detection helper
   * const { conditional, immediate } = await detectMediationCapabilities();
   * if (conditional) {
   *   authenticateWithFido2({
   *     mediation: 'conditional',
   *     statusCb: (status) => console.log(status),
   *     tokensCb: (tokens) => handleSignIn(tokens)
   *   });
   * }
   *
   * // Option 2: Full capabilities check (advanced)
   * const capabilities = await getClientCapabilities();
   * if (capabilities?.immediateGet) {
   *   try {
   *     await authenticateWithFido2({ mediation: 'immediate' }).signedIn;
   *   } catch (error) {
   *     // Library errors wrap the DOMException (error.name is never
   *     // 'NotAllowedError'); use the helper to detect this case
   *     if (isFido2NotAllowedError(error)) {
   *       // No local credentials - show password form
   *       showPasswordForm();
   *     }
   *   }
   * }
   *
   * // Option 3: Check multiple capabilities
   * if (capabilities?.passkeyPlatformAuthenticator) {
   *   // Show biometric icon
   * }
   * if (capabilities?.hybridTransport) {
   *   // Offer QR code option
   * }
   * ```
   *
   * @see https://passkeys.dev/docs/use-cases/bootstrapping (conditional)
   * @see https://developer.chrome.com/blog/webauthn-immediate-mediation (immediate)
   */
  mediation?: MediationMode;
  /**
   * Optional pre-fetched WebAuthn assertion bundle returned by prepareFido2SignIn().
   * When provided, authenticateWithFido2() will skip navigator.credentials.get()
   * and directly complete the Cognito challenge using this data.
   * Note: the bundle's Cognito session expires after `AuthSessionValidity`
   * minutes (3 by default), so use it promptly after preparation.
   */
  prepared?: PreparedFido2SignIn;
}) {
  if (currentStatus && busyState.includes(currentStatus as BusyState)) {
    throw new Error(`Can't sign in while in status ${currentStatus}`);
  }
  const abort = new AbortController();

  const { debug, fido2 } = configure();

  debug?.("🔑 authenticateWithFido2 called", {
    hasUsername: !!username,
    username: username ? `${username.substring(0, 3)}***` : undefined,
    hasPrepared: !!prepared,
    mediation,
    hasCredentials: !!credentials,
    credentialsCount: credentials?.length ?? 0,
  });

  // Monitor abort signal for this authentication session
  abort.signal.addEventListener("abort", () => {
    debug?.("⚠️ authenticateWithFido2: internal abort signal fired", {
      hasUsername: !!username,
      hasPrepared: !!prepared,
      mediation,
    });
  });

  const signedIn = (async () => {
    if (!fido2) {
      throw new Fido2ConfigError(
        "Fido2 configuration not initialized. Call configure() with fido2 options."
      );
    }
    statusCb?.("STARTING_SIGN_IN_WITH_FIDO2");

    if (prepared) {
      debug?.("📦 Using prepared FIDO2 bundle", {
        username: prepared.username,
        hasSession: !!prepared.session,
        hasCredential: !!prepared.credential,
        hasDeviceKey: !!prepared.existingDeviceKey,
      });
    }

    try {
      const preparedSignIn =
        prepared ??
        (await prepareFido2SignIn({
          username,
          credentials,
          credentialGetter,
          mediation,
          signal: abort.signal,
        }));

      if (username && username !== preparedSignIn.username) {
        throw new Fido2ValidationError(
          `Prepared credentials belong to username "${preparedSignIn.username}" but "${username}" was provided. Omit the username parameter or ensure it matches.`,
          {
            providedUsername: username,
            preparedUsername: preparedSignIn.username,
          }
        );
      }

      username = preparedSignIn.username;
      statusCb?.("COMPLETING_SIGN_IN_WITH_FIDO2");
      debug?.(`Invoking respondToAuthChallenge ...`);
      const challengeResponses: Record<string, string> = {
        ANSWER: JSON.stringify(preparedSignIn.credential),
        USERNAME: username,
        ...(preparedSignIn.existingDeviceKey
          ? { DEVICE_KEY: preparedSignIn.existingDeviceKey }
          : {}),
      };
      const authResult = await respondToAuthChallenge({
        challengeName: "CUSTOM_CHALLENGE",
        challengeResponses,
        clientMetadata: {
          ...clientMetadata,
          signInMethod: "FIDO2",
        },
        session: preparedSignIn.session,
        abort: abort.signal,
      });

      let tokens;
      if (isAuthenticatedResponse(authResult)) {
        debug?.(
          `Response from respondToAuthChallenge (tokens):`,
          redactTokensFromObject(authResult)
        );
        tokens = {
          accessToken: authResult.AuthenticationResult.AccessToken,
          idToken: authResult.AuthenticationResult.IdToken,
          refreshToken: authResult.AuthenticationResult.RefreshToken,
          expireAt: new Date(
            Date.now() + authResult.AuthenticationResult.ExpiresIn * 1000
          ),
          username: parseJwtPayload<CognitoIdTokenPayload>(
            authResult.AuthenticationResult.IdToken
          )["cognito:username"],
          newDeviceMetadata: authResult.AuthenticationResult.NewDeviceMetadata
            ? {
                deviceKey:
                  authResult.AuthenticationResult.NewDeviceMetadata.DeviceKey,
                deviceGroupKey:
                  authResult.AuthenticationResult.NewDeviceMetadata
                    .DeviceGroupKey,
              }
            : undefined,
        };
      } else {
        // Handle follow-up DEVICE_SRP_AUTH / DEVICE_PASSWORD_VERIFIER challenge chain
        debug?.(
          `Received follow-up challenge (${authResult.ChallengeName}). Delegating to handleAuthResponse.`
        );

        // Pre-create a device handler if we know the device key; if not, handleAuthResponse will create one lazily
        const deviceHandler = preparedSignIn.existingDeviceKey
          ? await createDeviceSrpAuthHandler(
              username,
              preparedSignIn.existingDeviceKey
            )
          : undefined;

        tokens = await handleAuthResponse({
          authResponse: authResult,
          username: username,
          deviceHandler,
          clientMetadata,
          abort: abort.signal,
        });
      }

      // Always process tokens first - this handles device confirmation, storage, and refresh scheduling
      const processedTokens = (await processTokens(
        {
          ...tokens,
          authMethod: "FIDO2",
        },
        abort.signal
      )) as TokensFromSignIn;

      // Then call the custom tokensCb if provided (for application-specific needs only)
      if (tokensCb) {
        await tokensCb(processedTokens);
      }

      statusCb?.("SIGNED_IN_WITH_FIDO2");
      return processedTokens;
    } catch (err) {
      if (
        mediation === "conditional" &&
        isFido2AbortError(err) &&
        err.superseded
      ) {
        // The conditional (autofill) request was aborted because a newer
        // credential request (e.g. a modal sign-in) took over. Don't change
        // status here: that would clobber the status of the sign-in flow that
        // took over. Caller-initiated aborts fall through to the SIGNED_OUT
        // handling below, so the UI still transitions out of its busy state
        debug?.(
          "Conditional FIDO2 sign-in was superseded by a newer credential request - not reporting failure status"
        );
        throw err;
      }
      if (
        isFido2AbortError(err) ||
        (err instanceof Error && err.name === "AbortError")
      ) {
        // Deliberate cancellation (e.g. the caller invoked abort()) is not a
        // sign-in failure: revert to the idle state the flow started from
        statusCb?.("SIGNED_OUT");
      } else {
        statusCb?.("FIDO2_SIGNIN_FAILED");
      }
      throw err;
    }
  })();
  return {
    signedIn,
    abort: () => abort.abort(),
  };
}
