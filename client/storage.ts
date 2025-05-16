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
}
export interface TokensFromStorage {
  accessToken?: string;
  idToken?: string;
  refreshToken?: string;
  expireAt?: Date;
  username: string;
  deviceKey?: string;
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
  const customKeyPrefix = `Passwordless.${clientId}`;

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

  promises.push(
    storage.setItem(
      `${customKeyPrefix}.${username}.expireAt`,
      tokens.expireAt.toISOString()
    )
  );

  // --------- 6. Execute writes ---------
  await Promise.all(promises.filter(Boolean));

  debug?.(
    `[storeTokens] Completed storage${tokens.refreshToken ? ", refreshToken stored under key " + amplifyKeyPrefix + "." + username + ".refreshToken" : ""}`
  );
}

export async function retrieveTokens(): Promise<TokensFromStorage | undefined> {
  const { clientId, storage } = configure();
  const amplifyKeyPrefix = `CognitoIdentityServiceProvider.${clientId}`;
  const customKeyPrefix = `Passwordless.${clientId}`;
  const username = await storage.getItem(`${amplifyKeyPrefix}.LastAuthUser`);
  if (!username) {
    return;
  }
  const [accessToken, idToken, refreshToken, expireAt] = await Promise.all([
    storage.getItem(`${amplifyKeyPrefix}.${username}.accessToken`),
    storage.getItem(`${amplifyKeyPrefix}.${username}.idToken`),
    storage.getItem(`${amplifyKeyPrefix}.${username}.refreshToken`),
    storage.getItem(`${customKeyPrefix}.${username}.expireAt`),
  ]);

  // Always get the device key separately, as it should persist across sessions
  const deviceKey = await retrieveDeviceKey(username);

  return {
    idToken: idToken ?? undefined,
    accessToken: accessToken ?? undefined,
    refreshToken: refreshToken ?? undefined,
    expireAt: expireAt ? new Date(expireAt) : undefined,
    username,
    deviceKey,
  };
}

/**
 * Store information about scheduled token refresh operations
 * This ensures consistency across hook remounts and even browser refreshes
 */
export async function storeRefreshScheduleInfo({
  isScheduled,
  expiryTime,
}: {
  isScheduled: boolean;
  expiryTime?: number;
}) {
  const { clientId, storage, debug } = configure();
  const scheduledKey = `Passwordless.${clientId}.refreshScheduled`;
  const expiryKey = `Passwordless.${clientId}.refreshExpiryTime`;

  debug?.(
    `Setting refresh scheduled status: ${isScheduled}, expiry: ${expiryTime}`
  );
  await storage.setItem(scheduledKey, isScheduled.toString());

  if (expiryTime) {
    await storage.setItem(expiryKey, expiryTime.toString());
  } else if (isScheduled === false) {
    // Clear expiry time when scheduling is disabled
    await storage.removeItem(expiryKey);
  }
}

/**
 * Check if a token refresh is already scheduled
 * @returns Object containing scheduling status and expiry time
 */
export async function getRefreshScheduleInfo(): Promise<{
  isScheduled: boolean;
  expiryTime?: number;
}> {
  const { clientId, storage } = configure();
  const scheduledKey = `Passwordless.${clientId}.refreshScheduled`;
  const expiryKey = `Passwordless.${clientId}.refreshExpiryTime`;

  const [isScheduledStr, expiryTimeStr] = await Promise.all([
    storage.getItem(scheduledKey),
    storage.getItem(expiryKey),
  ]);

  return {
    isScheduled: isScheduledStr === "true",
    expiryTime: expiryTimeStr ? parseInt(expiryTimeStr, 10) : undefined,
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
