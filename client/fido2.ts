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
  fromDOMException,
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
 *     await authenticateWithFido2({ mediation: 'immediate' });
 *   } catch (error) {
 *     if (error.name === 'NotAllowedError') {
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
  session: string;
  credential: ParsedFido2Assertion;
  existingDeviceKey?: string;
}

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
      id: Uint8Array.from(publicKeyOptions.user.id, (c) => c.charCodeAt(0)),
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
  if (!("challenge" in o) || typeof o.challenge !== "string") {
    throw new Fido2ValidationError(
      "Fido2 options must have a challenge string",
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

      if (!("id" in cred) || typeof cred.id !== "string") {
        throw new Fido2ValidationError(
          "Each credential must have an id string",
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
      try {
        const isAvailable =
          await PublicKeyCredential.isConditionalMediationAvailable();
        if (!isAvailable) {
          throw new Fido2ConfigError(
            "Conditional mediation requested but not supported by this browser."
          );
        }
      } catch (error) {
        debug?.(
          "⚠️ Cannot verify conditional mediation support - treating as unsupported",
          error
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
    // Conditional mediation requires "preferred" userVerification and no timeout
    effectiveUserVerification = "preferred";
    effectiveTimeout = undefined;

    if (userVerification && userVerification !== "preferred") {
      debug?.(
        `⚠️ WebAuthn spec requires userVerification="preferred" for conditional mediation. ` +
          `Overriding "${userVerification}" → "preferred"`
      );
    }
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

  debug?.("🚀 Calling navigator.credentials.get()", {
    mediation,
    hasSignal: !!signal,
    signalAborted: signal?.aborted,
    effectiveTimeout,
    effectiveUserVerification,
  });

  let credential;
  try {
    // Type assertion needed: 'immediate' mediation not yet in TS lib definitions (CredentialMediationRequirement)
    // Runtime support: Chrome 139+, see https://developer.chrome.com/blog/webauthn-immediate-mediation
    credential = await navigator.credentials.get({
      publicKey,
      signal,
      mediation: mediation as CredentialMediationRequirement,
    });
    debug?.("✅ navigator.credentials.get() succeeded");
  } catch (err) {
    if (err instanceof DOMException) {
      debug?.("❌ credentials.get() threw DOMException", {
        name: err.name,
        message: err.message,
        wasSignalAborted: signal?.aborted,
        mediation,
      });
      throw fromDOMException(err);
    }
    debug?.("❌ credentials.get() threw non-DOMException error", {
      error: err,
    });
    throw err;
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
    if (!initAuthResponse.ChallengeParameters.fido2options) {
      throw new Error("Server did not send a FIDO2 challenge");
    }

    const fido2options: unknown = JSON.parse(
      initAuthResponse.ChallengeParameters.fido2options
    );
    assertIsFido2Options(fido2options);
    debug?.("FIDO2 challenge received from Cognito");

    assertion = await credentialGetter({
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
      signal,
    });

    session = initAuthResponse.Session;
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
   * - userVerification automatically set to "preferred"
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
   *     await authenticateWithFido2({ mediation: 'immediate' });
   *   } catch (error) {
   *     if (error.name === 'NotAllowedError') {
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
        debug?.(`Response from respondToAuthChallenge (tokens):`, authResult);
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
      statusCb?.("FIDO2_SIGNIN_FAILED");
      throw err;
    }
  })();
  return {
    signedIn,
    abort: () => abort.abort(),
  };
}
