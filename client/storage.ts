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
  idToken: string;
  refreshToken?: string;
  expireAt: Date;
  deviceKey?: string;
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
  const { clientId, storage } = configure();

  // Extract username from tokens or from the id token
  let username = tokens.username;
  if (!username) {
    const payload = parseJwtPayload<CognitoIdTokenPayload>(tokens.idToken);
    username = payload["cognito:username"];

    // Verify we have a username
    if (!username) {
      throw new Error("Could not determine username when storing tokens");
    }
  }

  // Get the payload of the access token to extract the scope
  const { scope } = parseJwtPayload<CognitoAccessTokenPayload>(
    tokens.accessToken
  );
  const amplifyKeyPrefix = `CognitoIdentityServiceProvider.${clientId}`;
  const customKeyPrefix = `Passwordless.${clientId}`;

  const promises: (void | Promise<void>)[] = [];
  promises.push(storage.setItem(`${amplifyKeyPrefix}.LastAuthUser`, username));
  promises.push(
    storage.setItem(`${amplifyKeyPrefix}.${username}.idToken`, tokens.idToken)
  );
  promises.push(
    storage.setItem(
      `${amplifyKeyPrefix}.${username}.accessToken`,
      tokens.accessToken
    )
  );
  if (tokens.refreshToken) {
    promises.push(
      storage.setItem(
        `${amplifyKeyPrefix}.${username}.refreshToken`,
        tokens.refreshToken
      )
    );
  }

  // If a device key is provided and we know the username,
  // store it in the RememberedDeviceRecord so it persists
  if (tokens.deviceKey && username) {
    promises.push(storeDeviceKey(username, tokens.deviceKey));
  }

  // Also store user data from the id token
  const payload = parseJwtPayload<CognitoIdTokenPayload>(tokens.idToken);
  promises.push(
    storage.setItem(
      `${amplifyKeyPrefix}.${username}.userData`,
      JSON.stringify({
        UserAttributes: [
          {
            Name: "sub",
            Value: payload.sub,
          },
          {
            Name: "email",
            Value: payload.email,
          },
        ],
        Username: username,
      })
    )
  );
  promises.push(
    storage.setItem(`${amplifyKeyPrefix}.${username}.tokenScopesString`, scope)
  );
  promises.push(
    storage.setItem(
      `${customKeyPrefix}.${username}.expireAt`,
      tokens.expireAt.toISOString()
    )
  );
  await Promise.all(promises.filter((p) => !!p));
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
