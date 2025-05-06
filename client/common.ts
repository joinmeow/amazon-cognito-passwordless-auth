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
import { revokeToken, confirmDevice } from "./cognito-api.js";
import { configure } from "./config.js";
import { retrieveTokens, storeTokens, storeDeviceKey } from "./storage.js";
import {
  TokensFromRefresh,
  TokensFromSignIn,
  BusyState,
  IdleState,
  busyState,
} from "./model.js";
import { scheduleRefresh } from "./refresh.js";
import { bufferToBase64 } from "./util.js";

/**
 * Automatically handle device confirmation when NewDeviceMetadata is present in tokens.
 * This should be called after successful authentication when NewDeviceMetadata is available.
 * Note: This only confirms the device. If UserConfirmationNecessary is true, the application
 * should ask the user if they want to remember the device and call updateDeviceStatus separately.
 *
 * @param tokens The tokens from sign-in that contain NewDeviceMetadata
 * @param deviceName Optional device name, defaults to "My Device"
 * @returns The updated tokens with deviceKey set and a userConfirmationNecessary flag
 */
export async function handleDeviceConfirmation(
  tokens: TokensFromSignIn,
  deviceName: string = "My Device"
): Promise<TokensFromSignIn & { userConfirmationNecessary?: boolean }> {
  const { debug, crypto } = configure();

  // Check if we have NewDeviceMetadata with deviceKey
  if (!tokens.newDeviceMetadata?.deviceKey) {
    debug?.("No new device metadata present, skipping device confirmation");
    return tokens;
  }

  const deviceKey = tokens.newDeviceMetadata.deviceKey;
  debug?.("Confirming new device with key:", deviceKey);

  if (!tokens.accessToken) {
    throw new Error("Missing access token required for device confirmation");
  }

  try {
    // Generate a random salt
    const saltBuffer = new Uint8Array(16);
    crypto.getRandomValues(saltBuffer);
    const salt = bufferToBase64(saltBuffer);

    // Generate a random password verifier
    const passwordVerifierBuffer = new Uint8Array(64);
    crypto.getRandomValues(passwordVerifierBuffer);
    const passwordVerifier = bufferToBase64(passwordVerifierBuffer);

    // Create device verifier config
    const deviceVerifierConfig = {
      passwordVerifier,
      salt,
    };

    // Call confirmDevice with the device key
    const result = await confirmDevice({
      accessToken: tokens.accessToken,
      deviceKey,
      deviceName,
      deviceSecretVerifierConfig: deviceVerifierConfig,
    });

    debug?.("Device confirmation result:", result);

    // Note whether user confirmation is necessary
    // Important: We DO NOT automatically call updateDeviceStatus here anymore
    // The application should ask the user if they want to remember the device
    // and call updateDeviceStatus separately if they say yes
    if (result.UserConfirmationNecessary) {
      debug?.(
        "User confirmation necessary for device. Application should ask user if they want to remember this device."
      );
    } else {
      debug?.("Device automatically remembered based on user pool settings.");
    }

    // Store the device key in persistent storage
    await storeDeviceKey(deviceKey);

    // Set the deviceKey in the tokens
    tokens.deviceKey = deviceKey;

    debug?.("Device confirmation completed successfully");
    return {
      ...tokens,
      userConfirmationNecessary: result.UserConfirmationNecessary,
    };
  } catch (error) {
    debug?.("Error during device confirmation:", error);
    // Even if device confirmation fails, we still want to store the device key
    // so we can try to use it for future authentication attempts
    tokens.deviceKey = deviceKey;
    await storeDeviceKey(deviceKey);
    return tokens;
  }
}

/** The default tokens callback stores tokens in storage and reschedules token refresh */
export const defaultTokensCb = async ({
  tokens,
  abort,
}: {
  tokens: TokensFromSignIn | TokensFromRefresh;
  abort?: AbortSignal;
}) => {
  const storeAndScheduleRefresh = async (
    tokens: TokensFromSignIn | TokensFromRefresh
  ) => {
    // If this is a sign-in with a new device, extract the device key
    if ("newDeviceMetadata" in tokens && tokens.newDeviceMetadata?.deviceKey) {
      const { debug } = configure();
      debug?.("Detected new device metadata with device key");

      // Complete device confirmation if this is a sign-in (has accessToken)
      if ("accessToken" in tokens && "newDeviceMetadata" in tokens) {
        // We can safely cast to TokensFromSignIn here since we've checked for newDeviceMetadata
        tokens = await handleDeviceConfirmation(tokens);
      } else {
        // Set the deviceKey field in tokens
        tokens.deviceKey = tokens.newDeviceMetadata.deviceKey;

        // Store the device key separately for persistence
        await storeDeviceKey(tokens.newDeviceMetadata.deviceKey);
      }
    }

    await storeTokens(tokens);
    scheduleRefresh({
      abort,
      tokensCb: (newTokens) => {
        if (!newTokens) return;

        // Create combined tokens object, preserving important fields
        const combinedTokens = {
          ...tokens,
          ...newTokens,
          // Ensure deviceKey persists (newTokens from refresh won't have it)
          deviceKey: tokens.deviceKey || newTokens.deviceKey,
          // Preserve userConfirmationNecessary if present
          userConfirmationNecessary:
            "userConfirmationNecessary" in tokens
              ? tokens.userConfirmationNecessary
              : undefined,
        };

        return storeAndScheduleRefresh(combinedTokens);
      },
    }).catch((err) => {
      const { debug } = configure();
      debug?.("Failed to store and refresh tokens:", err);
    });
  };
  await storeAndScheduleRefresh(tokens);
};

/**
 * Sign the user out. This means: clear tokens from storage,
 * and revoke the refresh token from Amazon Cognito
 * Note: The device key is preserved to enable device authentication on next login
 */
export const signOut = (props?: {
  currentStatus?: BusyState | IdleState;
  tokensRemovedLocallyCb?: () => void;
  statusCb?: (status: BusyState | IdleState) => void;
  skipTokenRevocation?: boolean;
}) => {
  const { clientId, debug, storage } = configure();
  const { currentStatus, statusCb, skipTokenRevocation } = props ?? {};
  if (currentStatus && busyState.includes(currentStatus as BusyState)) {
    debug?.(
      `Initiating sign-out despite being in a busy state: ${currentStatus}`
    );
  }
  statusCb?.("SIGNING_OUT");
  const abort = new AbortController();

  const tokenRevocationTracker = new Set<string>();

  const signedOut = (async () => {
    try {
      const tokens = await retrieveTokens();
      if (abort.signal.aborted) {
        debug?.("Aborting sign-out");
        currentStatus && statusCb?.(currentStatus);
        return;
      }
      if (!tokens) {
        debug?.("No tokens in storage to delete");
        props?.tokensRemovedLocallyCb?.();
        statusCb?.("SIGNED_OUT");
        return;
      }
      const amplifyKeyPrefix = `CognitoIdentityServiceProvider.${clientId}`;
      const customKeyPrefix = `Passwordless.${clientId}`;
      await Promise.all([
        storage.removeItem(`${amplifyKeyPrefix}.${tokens.username}.idToken`),
        storage.removeItem(
          `${amplifyKeyPrefix}.${tokens.username}.accessToken`
        ),
        storage.removeItem(
          `${amplifyKeyPrefix}.${tokens.username}.refreshToken`
        ),
        storage.removeItem(
          `${amplifyKeyPrefix}.${tokens.username}.tokenScopesString`
        ),
        storage.removeItem(`${amplifyKeyPrefix}.${tokens.username}.userData`),
        storage.removeItem(`${amplifyKeyPrefix}.LastAuthUser`),
        storage.removeItem(`${customKeyPrefix}.${tokens.username}.expireAt`),
        storage.removeItem(
          `Passwordless.${clientId}.${tokens.username}.refreshingTokens`
        ),
        // Note: We do NOT remove deviceKey - it should persist between sessions
      ]);
      props?.tokensRemovedLocallyCb?.();

      if (
        tokens.refreshToken &&
        !tokenRevocationTracker.has(tokens.refreshToken) &&
        !skipTokenRevocation
      ) {
        try {
          tokenRevocationTracker.add(tokens.refreshToken);
          await revokeToken({
            abort: undefined,
            refreshToken: tokens.refreshToken,
          });
          debug?.("Successfully revoked refresh token");
        } catch (revokeError) {
          debug?.(
            "Error revoking token, but continuing sign-out process:",
            revokeError
          );
        }
      }

      statusCb?.("SIGNED_OUT");
    } catch (err) {
      if (abort.signal.aborted) return;
      debug?.("Error during sign-out:", err);
      currentStatus && statusCb?.(currentStatus);
      throw err;
    }
  })();
  return {
    signedOut,
    abort: () => abort.abort(),
  };
};
