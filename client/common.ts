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

// Helper function to get device info for naming
function getDeviceName(): string {
  if (typeof navigator === "undefined") {
    return "Unknown Device";
  }

  const ua = navigator.userAgent;

  // Get OS type
  let os = "Unknown";
  if (ua.includes("iPhone")) os = "iPhone";
  else if (ua.includes("iPad")) os = "iPad";
  else if (ua.includes("Android")) os = "Android";
  else if (ua.includes("Windows")) os = "Windows";
  else if (ua.includes("Mac")) os = "Mac";
  else if (ua.includes("Linux")) os = "Linux";

  // Get browser type
  let browser = "";
  if (ua.includes("Chrome") && !ua.includes("Edg")) browser = "Chrome";
  else if (ua.includes("Firefox")) browser = "Firefox";
  else if (ua.includes("Safari") && !ua.includes("Chrome")) browser = "Safari";
  else if (ua.includes("Edg")) browser = "Edge";

  return browser ? `${os} ${browser}` : os;
}

/**
 * Automatically handle device confirmation for authentication flows when NewDeviceMetadata is present.
 * This confirms the device using the device key provided in the authentication response.
 * We NEVER generate a device key - only use what Cognito provides.
 *
 * @param tokens The tokens from sign-in with newDeviceMetadata
 * @param deviceName Optional device name, defaults to auto-detected device type
 * @returns The updated tokens with deviceKey set and a userConfirmationNecessary flag
 */
export async function handleDeviceConfirmation(
  tokens: TokensFromSignIn,
  deviceName?: string
): Promise<TokensFromSignIn & { userConfirmationNecessary?: boolean }> {
  const { debug, crypto } = configure();

  // We MUST have newDeviceMetadata with a deviceKey to confirm a device
  if (!tokens.newDeviceMetadata?.deviceKey) {
    debug?.("No new device metadata present, skipping device confirmation");
    return tokens;
  }

  const deviceKey = tokens.newDeviceMetadata.deviceKey;
  debug?.("Confirming device with key:", deviceKey);

  if (!tokens.accessToken) {
    throw new Error("Missing access token required for device confirmation");
  }

  // Use provided name or detect device type
  const finalDeviceName = deviceName || getDeviceName();
  debug?.("Using device name:", finalDeviceName);

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
      deviceName: finalDeviceName,
      deviceSecretVerifierConfig: deviceVerifierConfig,
    });

    debug?.("Device confirmation result:", result);

    // Note whether user confirmation is necessary
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

/**
 * Process tokens after authentication or refresh.
 * This function handles ALL required operations:
 * 1. Device confirmation
 * 2. Token storage
 * 3. Scheduling token refresh
 *
 * This MUST be called for all auth flows before any custom callbacks.
 *
 * @param tokens The tokens to process
 * @param abort Optional abort signal
 * @returns The processed tokens (with device key and other metadata)
 */
export async function processTokens(
  tokens: TokensFromSignIn | TokensFromRefresh,
  abort?: AbortSignal
): Promise<TokensFromSignIn | TokensFromRefresh> {
  const { debug } = configure();

  // 1. Process device confirmation if needed
  if ("newDeviceMetadata" in tokens && tokens.newDeviceMetadata?.deviceKey) {
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
  // We only confirm devices when NewDeviceMetadata is provided by Cognito
  // Never attempt to generate a device key or confirm without explicit metadata

  // 2. Store tokens for persistence
  await storeTokens(tokens);

  // 3. Schedule refresh if we have a refresh token
  if (tokens.refreshToken) {
    scheduleRefresh({
      abort,
      tokensCb: (newTokens) => {
        if (!newTokens) return;

        // We don't need to store tokens here because processTokens will be called
        // for the refresh tokens too, and it will store them.

        return Promise.resolve();
      },
    }).catch((err) => {
      debug?.("Failed to schedule token refresh:", err);
    });
  }

  return tokens;
}

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
