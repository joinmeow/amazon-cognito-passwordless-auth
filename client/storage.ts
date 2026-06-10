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
import { parseJwtPayload } from "./util.js";
import { configure } from "./config.js";
import {
  CognitoIdTokenPayload,
  CognitoAccessTokenPayload,
} from "./jwt-model.js";

export interface TokensToStore {
  accessToken: string;
  /**
   * ID token returned by Cognito. Optional because certain OAuth flows
   * (e.g. custom authorization servers) may omit it. All logic that depends
   * on the ID token must therefore handle the undefined case.
   */
  idToken?: string;
  refreshToken?: string;
  expireAt: Date;
  deviceKey?: string;
  /**
   * Optional pre-resolved username. If not provided we will attempt to
   * derive it from either the ID-token (preferred) or from the access token.
   */
  username?: string;
  /**
   * The authentication method used to obtain these tokens
   * Helps the refresh mechanism determine how to refresh tokens
   */
  authMethod?: "SRP" | "FIDO2" | "PLAINTEXT" | "REDIRECT";
  /**
   * Client clock drift (ms) captured at token receipt (local time minus the
   * access token's `iat`). Persisted so token expiry can be evaluated against
   * a skew-corrected clock. Absent => treated as 0 (previous behavior).
   */
  clockDriftMs?: number;
}
export interface TokensFromStorage {
  accessToken?: string;
  idToken?: string;
  refreshToken?: string;
  expireAt?: Date;
  username: string;
  deviceKey?: string;
  /** The authentication method used with these tokens */
  authMethod?: "SRP" | "FIDO2" | "PLAINTEXT" | "REDIRECT";
  /** Client clock drift (ms) captured at token receipt; 0 when unknown. */
  clockDriftMs?: number;
}

type TokensStoredListener = (tokens: TokensToStore) => void;

// In-memory registry of same-context subscribers, notified whenever tokens
// are persisted via storeTokens. Needed because the WHATWG "storage" event
// only fires in *other* documents, never in the document that performed the
// write — so without this, a background token refresh in the active tab
// would update storage without any way for UI state (e.g. the React hook)
// to find out.
const tokensStoredListeners = new Set<TokensStoredListener>();

/**
 * Subscribe to token stores performed in this JavaScript context.
 * The listener is invoked after the tokens have been persisted to storage.
 *
 * @param listener Called with the tokens that were just stored
 * @returns A function that unsubscribes the listener
 */
export function onTokensStored(listener: TokensStoredListener): () => void {
  tokensStoredListeners.add(listener);
  return () => {
    tokensStoredListeners.delete(listener);
  };
}

/**
 * Store the authentication method used for the current user
 * This helps refresh token logic determine how to refresh tokens
 */
export async function storeAuthMethod(
  username: string,
  authMethod: "SRP" | "FIDO2" | "PLAINTEXT" | "REDIRECT"
) {
  if (!username) return;
  const { clientId, storage, debug } = configure();
  const key = `Passwordless.${clientId}.${username}.authMethod`;
  debug?.(`Storing auth method for ${username}: ${authMethod}`);
  await storage.setItem(key, authMethod);
}

/**
 * Retrieve the authentication method used for the current user
 * Used by refresh token logic to determine how to refresh tokens
 */
export async function retrieveAuthMethod(
  username: string
): Promise<"SRP" | "FIDO2" | "PLAINTEXT" | "REDIRECT" | undefined> {
  if (!username) return undefined;
  const { clientId, storage } = configure();
  const key = `Passwordless.${clientId}.${username}.authMethod`;
  const authMethod = await storage.getItem(key);

  if (
    authMethod === "SRP" ||
    authMethod === "FIDO2" ||
    authMethod === "PLAINTEXT" ||
    authMethod === "REDIRECT"
  ) {
    return authMethod;
  }

  return undefined;
}

/**
 * Retrieve the client clock drift (ms) captured at the last token receipt.
 * Returns 0 when not present (e.g. legacy tokens stored before this field
 * existed), preserving the prior uncorrected behavior for those.
 */
export async function retrieveClockDriftMs(username: string): Promise<number> {
  if (!username) return 0;
  const { clientId, storage } = configure();
  const key = `CognitoIdentityServiceProvider.${clientId}.${username}.clockDriftMs`;
  const raw = await storage.getItem(key);
  if (!raw) return 0;
  const n = Number(raw);
  return Number.isFinite(n) ? n : 0;
}

export async function storeTokens(tokens: TokensToStore) {
  const { clientId, storage, debug } = configure();
  debug?.("[storeTokens] tokens to store:", tokens);

  // --------- 1. Derive username ---------
  let username = tokens.username;

  // Prefer extracting from the *access* token because
  // 1) it is always present (required for any Cognito auth flow) and
  // 2) the field name is a simple `username`, avoiding the Cognito-specific
  //    "cognito:username" key present in the ID token.
  if (!username) {
    const accessPayload = parseJwtPayload<CognitoAccessTokenPayload>(
      tokens.accessToken
    );
    username = accessPayload.username;

    // Fallback to ID-token if access token didn't contain it (edge-case when
    // using a custom authorizer that strips the field).
    if (!username && tokens.idToken) {
      const idPayload = parseJwtPayload<CognitoIdTokenPayload>(tokens.idToken);
      username = idPayload["cognito:username"];
    }

    if (!username) {
      throw new Error("Could not determine username when storing tokens");
    }
  }

  // --------- 2. Prepare key prefixes ---------
  const amplifyKeyPrefix = `CognitoIdentityServiceProvider.${clientId}`;

  // --------- 3. Parse access token for scope (always present) ---------
  const { scope: accessTokenScope, sub: accessSub } =
    parseJwtPayload<CognitoAccessTokenPayload>(tokens.accessToken);

  // --------- 4. Queue write operations ---------
  const promises: (void | Promise<void>)[] = [];

  promises.push(storage.setItem(`${amplifyKeyPrefix}.LastAuthUser`, username));

  // Store ID token if available
  if (tokens.idToken) {
    promises.push(
      storage.setItem(`${amplifyKeyPrefix}.${username}.idToken`, tokens.idToken)
    );
  }

  // Access token is always present
  promises.push(
    storage.setItem(
      `${amplifyKeyPrefix}.${username}.accessToken`,
      tokens.accessToken
    )
  );

  // Store refresh token if provided
  if (tokens.refreshToken) {
    debug?.(
      `[storeTokens] Writing refreshToken for ${username} to key ${amplifyKeyPrefix}.${username}.refreshToken`
    );
    promises.push(
      storage.setItem(
        `${amplifyKeyPrefix}.${username}.refreshToken`,
        tokens.refreshToken
      )
    );
  }

  // Store auth method if provided - this is critical for refresh token handling
  if (tokens.authMethod) {
    debug?.(
      `[storeTokens] Storing auth method for ${username}: ${tokens.authMethod}`
    );
    promises.push(storeAuthMethod(username, tokens.authMethod));
  }

  // Persist device key if supplied
  if (tokens.deviceKey) {
    promises.push(storeDeviceKey(username, tokens.deviceKey));
  }

  // --------- 5. Store user data (sub + optional email) ---------
  let sub: string | undefined;
  let email: string | undefined;

  if (tokens.idToken) {
    const payloadId = parseJwtPayload<CognitoIdTokenPayload>(tokens.idToken);
    sub = payloadId.sub;
    email = payloadId.email;
  } else {
    // Fall back to access token for sub. Email is not available in access token
    sub = accessSub;
  }

  const userAttributes: { Name: string; Value: string | undefined }[] = [
    { Name: "sub", Value: sub },
  ];
  if (email) {
    userAttributes.push({ Name: "email", Value: email });
  }

  promises.push(
    storage.setItem(
      `${amplifyKeyPrefix}.${username}.userData`,
      JSON.stringify({
        UserAttributes: userAttributes,
        Username: username,
      })
    )
  );

  promises.push(
    storage.setItem(
      `${amplifyKeyPrefix}.${username}.tokenScopesString`,
      accessTokenScope
    )
  );

  // Persist the clock drift captured at token receipt so expiry can later be
  // evaluated against a skew-corrected clock (see retrieveTokens). Only written
  // when known, so legacy/test paths that don't set it default to 0.
  if (
    typeof tokens.clockDriftMs === "number" &&
    Number.isFinite(tokens.clockDriftMs)
  ) {
    promises.push(
      storage.setItem(
        `${amplifyKeyPrefix}.${username}.clockDriftMs`,
        String(Math.round(tokens.clockDriftMs))
      )
    );
  }

  // --------- 6. Execute writes ---------
  await Promise.all(promises.filter(Boolean));

  debug?.(
    `[storeTokens] Completed storage${tokens.refreshToken ? ", refreshToken stored under key " + amplifyKeyPrefix + "." + username + ".refreshToken" : ""}`
  );

  // --------- 7. Notify same-context subscribers ---------
  // The "storage" event never fires in the document that performed the write,
  // so subscribers in this context (e.g. the React hook) rely on this callback
  // to pick up tokens written by background refreshes in the same tab.
  for (const listener of tokensStoredListeners) {
    try {
      listener(tokens);
    } catch (err) {
      debug?.("[storeTokens] onTokensStored listener threw:", err);
    }
  }
}

export async function retrieveTokens(): Promise<TokensFromStorage | undefined> {
  const { clientId, storage } = configure();
  const amplifyKeyPrefix = `CognitoIdentityServiceProvider.${clientId}`;
  const username = await storage.getItem(`${amplifyKeyPrefix}.LastAuthUser`);
  if (!username) {
    return;
  }
  const [accessToken, idToken, refreshToken] = await Promise.all([
    storage.getItem(`${amplifyKeyPrefix}.${username}.accessToken`),
    storage.getItem(`${amplifyKeyPrefix}.${username}.idToken`),
    storage.getItem(`${amplifyKeyPrefix}.${username}.refreshToken`),
  ]);

  // ---------- 🔐  Derive reliable expiry timestamp ----------
  let expireAtDate: Date | undefined;
  const { debug } = configure();

  if (accessToken) {
    try {
      const { exp } = parseJwtPayload<CognitoAccessTokenPayload>(accessToken);
      if (typeof exp === "number" && exp > 0) {
        expireAtDate = new Date(exp * 1000);
      }
    } catch (err) {
      debug?.("[retrieveTokens] Failed to parse exp from accessToken:", err);
    }
  }

  // Evaluate expiry against a skew-corrected "now" (local clock minus the drift
  // captured at token receipt). This prevents a wrong device clock from making
  // valid, freshly-issued tokens look expired and dropping the whole session.
  const clockDriftMs = await retrieveClockDriftMs(username);
  const correctedNow = Date.now() - clockDriftMs;

  // Safety-net: if we don't have a valid future expiry timestamp, discard all tokens
  if (!expireAtDate || expireAtDate.valueOf() <= correctedNow) {
    debug?.(
      "[retrieveTokens] Tokens missing valid future expiry. Dropping cached tokens."
    );
    return undefined;
  }

  // Always get the device key separately, as it should persist across sessions
  const deviceKey = await retrieveDeviceKey(username);

  // Get the stored auth method for this user
  const authMethod = await retrieveAuthMethod(username);

  return {
    idToken: idToken ?? undefined,
    accessToken: accessToken ?? undefined,
    refreshToken: refreshToken ?? undefined,
    expireAt: expireAtDate,
    username,
    deviceKey,
    authMethod,
    clockDriftMs,
  };
}

/**
 * Retrieve tokens for refresh purposes, including expired tokens.
 * This is needed because the refresh system needs to see expired tokens
 * to trigger immediate refresh.
 */
export async function retrieveTokensForRefresh(): Promise<
  TokensFromStorage | undefined
> {
  const { clientId, storage } = configure();
  const amplifyKeyPrefix = `CognitoIdentityServiceProvider.${clientId}`;
  const username = await storage.getItem(`${amplifyKeyPrefix}.LastAuthUser`);
  if (!username) {
    return;
  }

  const [accessToken, idToken, refreshToken] = await Promise.all([
    storage.getItem(`${amplifyKeyPrefix}.${username}.accessToken`),
    storage.getItem(`${amplifyKeyPrefix}.${username}.idToken`),
    storage.getItem(`${amplifyKeyPrefix}.${username}.refreshToken`),
  ]);

  // If no refresh token, can't refresh
  if (!refreshToken) {
    return;
  }

  // Try to get expiry from access token
  let expireAtDate: Date | undefined;
  const { debug } = configure();

  if (accessToken) {
    try {
      const { exp } = parseJwtPayload<CognitoAccessTokenPayload>(accessToken);
      if (typeof exp === "number" && exp > 0) {
        expireAtDate = new Date(exp * 1000);
      }
    } catch (err) {
      debug?.(
        "[retrieveTokensForRefresh] Failed to parse exp from accessToken:",
        err
      );
    }
  }

  // For refresh purposes, we need tokens even if expired
  if (!expireAtDate) {
    debug?.(
      "[retrieveTokensForRefresh] No expiry date found, but continuing for refresh"
    );
    // Set a past date to trigger immediate refresh
    expireAtDate = new Date(Date.now() - 1);
  }

  // Get device key and auth method
  const deviceKey = await retrieveDeviceKey(username);
  const authMethod = await retrieveAuthMethod(username);
  const clockDriftMs = await retrieveClockDriftMs(username);

  return {
    idToken: idToken ?? undefined,
    accessToken: accessToken ?? undefined,
    refreshToken: refreshToken ?? undefined,
    expireAt: expireAtDate,
    username,
    deviceKey,
    authMethod,
    clockDriftMs,
  };
}

export interface RememberedDeviceRecord {
  deviceKey: string;
  groupKey: string;
  password: string;
  remembered: boolean;
}

function buildDeviceStorageKey(clientId: string, username: string) {
  return `Passwordless.${clientId}.device.${username}`;
}

/**
 * Persist (or overwrite) a device record for a given username.
 */
export async function setRememberedDevice(
  username: string,
  record: RememberedDeviceRecord
) {
  const { clientId, storage, debug } = configure();
  const key = buildDeviceStorageKey(clientId, username);
  debug?.(`Saving remembered device for user ${username}: ${record.deviceKey}`);
  await storage.setItem(key, JSON.stringify(record));
}

/**
 * Retrieve the device record for a user, migrating legacy per-device keys if necessary.
 */
export async function getRememberedDevice(
  username: string
): Promise<RememberedDeviceRecord | undefined> {
  const { clientId, storage } = configure();
  const key = buildDeviceStorageKey(clientId, username);
  const raw = await storage.getItem(key);
  if (raw) {
    try {
      return JSON.parse(raw) as RememberedDeviceRecord;
    } catch {
      // Corrupted JSON – remove it.
      await storage.removeItem(key);
      return undefined;
    }
  }

  return undefined;
}

/**
 * Remove the remembered device for a user (e.g. after ForgetDevice).
 */
export async function clearRememberedDevice(username: string) {
  const { clientId, storage, debug } = configure();
  const key = buildDeviceStorageKey(clientId, username);
  debug?.(`Clearing remembered device for user ${username}`);
  await storage.removeItem(key);
}

/**
 * Store the device key by creating/updating the device record for a user.
 * Sets a basic RememberedDeviceRecord with empty placeholders for non-key values.
 */
export async function storeDeviceKey(username: string, deviceKey: string) {
  if (!username || !deviceKey) return;
  const { debug } = configure();
  debug?.(`Storing device key for ${username}: ${deviceKey}`);

  // Check if we already have a record for this user
  const existingRecord = await getRememberedDevice(username);

  if (existingRecord?.deviceKey === deviceKey) {
    // No change needed
    return;
  }

  // Create/update the record
  await setRememberedDevice(username, {
    deviceKey,
    groupKey: existingRecord?.groupKey || "", // Keep existing or empty placeholder
    password: existingRecord?.password || "", // Keep existing or empty placeholder
    remembered: existingRecord?.remembered || false, // Default to not remembered
  });
}

/**
 * Retrieve just the device key from the user's RememberedDeviceRecord.
 */
export async function retrieveDeviceKey(
  username: string
): Promise<string | undefined> {
  if (!username) return undefined;
  const record = await getRememberedDevice(username);
  return record?.deviceKey;
}
