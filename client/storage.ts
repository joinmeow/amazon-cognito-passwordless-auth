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

/**
 * Store the device key separately from tokens so it persists even after logout
 * @param deviceKey The device key to store
 */
export async function storeDeviceKey(deviceKey: string) {
  if (!deviceKey) return;
  const { clientId, storage, debug } = configure();
  const deviceKeyStorageKey = `Passwordless.${clientId}.deviceKey`;
  debug?.(`Storing device key: ${deviceKey}`);
  await storage.setItem(deviceKeyStorageKey, deviceKey);
}

/**
 * Retrieve the stored device key
 */
export async function retrieveDeviceKey(): Promise<string | undefined> {
  const { clientId, storage } = configure();
  const deviceKeyStorageKey = `Passwordless.${clientId}.deviceKey`;
  const deviceKey = await storage.getItem(deviceKeyStorageKey);
  return deviceKey || undefined;
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

  // If a device key is provided, store it separately so it persists after logout
  if (tokens.deviceKey) {
    promises.push(storeDeviceKey(tokens.deviceKey));
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
  const deviceKey = await retrieveDeviceKey();

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
 * Store device remembered status
 * @param deviceKey The device key
 * @param isRemembered Whether the device should be remembered
 */
export async function storeDeviceRememberedStatus(
  deviceKey: string,
  isRemembered: boolean
) {
  if (!deviceKey) return;
  const { clientId, storage, debug } = configure();
  const deviceRememberedKey = `Passwordless.${clientId}.deviceRemembered.${deviceKey}`;
  debug?.(`Setting device ${deviceKey} remembered status: ${isRemembered}`);
  await storage.setItem(deviceRememberedKey, isRemembered.toString());
}

/**
 * Check if a device is remembered
 * @param deviceKey The device key to check
 * @returns Whether the device is remembered
 */
export async function isDeviceRemembered(deviceKey?: string): Promise<boolean> {
  if (!deviceKey) return false;
  const { clientId, storage } = configure();
  const deviceRememberedKey = `Passwordless.${clientId}.deviceRemembered.${deviceKey}`;
  const remembered = await storage.getItem(deviceRememberedKey);
  return remembered === "true";
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

/**
 * Store device password for device authentication
 * @param deviceKey The device key
 * @param devicePassword The device password to store
 */
export async function storeDevicePassword(
  deviceKey: string,
  devicePassword: string
) {
  if (!deviceKey) return;
  const { clientId, storage, debug } = configure();
  const devicePasswordKey = `Passwordless.${clientId}.devicePassword.${deviceKey}`;
  debug?.(`Storing password for device: ${deviceKey}`);
  await storage.setItem(devicePasswordKey, devicePassword);
}

/**
 * Retrieve stored device password
 * @param deviceKey The device key to retrieve the password for
 * @returns The device password if found, otherwise undefined
 */
export async function retrieveDevicePassword(
  deviceKey?: string
): Promise<string | undefined> {
  if (!deviceKey) return undefined;
  const { clientId, storage } = configure();
  const devicePasswordKey = `Passwordless.${clientId}.devicePassword.${deviceKey}`;
  const password = await storage.getItem(devicePasswordKey);
  return password || undefined;
}
