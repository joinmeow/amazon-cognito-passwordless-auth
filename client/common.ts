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
import { revokeToken } from "./cognito-api.js";
import { configure } from "./config.js";
import {
  retrieveTokens,
  storeTokens,
  storeDeviceKey,
  isDeviceRemembered,
  storeDeviceRememberedStatus,
} from "./storage.js";
import {
  TokensFromRefresh,
  TokensFromSignIn,
  BusyState,
  IdleState,
  busyState,
} from "./model.js";
import { scheduleRefresh } from "./refresh.js";
import { handleDeviceConfirmation } from "./device.js";

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
      // According to AWS docs, we should always confirm a device after successful auth
      // The purpose of device confirmation is to prepare for future MFA bypass,
      // not to require MFA for confirmation
      debug?.(
        "Proceeding with device confirmation after successful authentication"
      );

      // We can safely cast to TokensFromSignIn here since we've checked for newDeviceMetadata
      tokens = await handleDeviceConfirmation(tokens);
    } else {
      // Set the deviceKey field in tokens
      tokens.deviceKey = tokens.newDeviceMetadata.deviceKey;

      // Store the device key separately for persistence
      await storeDeviceKey(tokens.newDeviceMetadata.deviceKey);

      // By default, device is not remembered unless explicitly confirmed
      // through handleDeviceConfirmation
      await storeDeviceRememberedStatus(
        tokens.newDeviceMetadata.deviceKey,
        false
      );
    }
  } else if (tokens.deviceKey) {
    // If we have a device key but no new metadata, check if it's remembered
    const remembered = await isDeviceRemembered(tokens.deviceKey);
    debug?.(
      `Using existing device key ${tokens.deviceKey}, remembered: ${remembered}`
    );
  }
  // We only confirm devices when NewDeviceMetadata is provided by Cognito
  // Never attempt to generate a device key or confirm without explicit metadata

  // 2. Store tokens for persistence
  await storeTokens(tokens);

  // 3. Schedule refresh if we have a refresh token
  // But only if this is NOT a fresh login (indicated by newDeviceMetadata)
  // This prevents immediate refresh scheduling right after login
  if (tokens.refreshToken && !("newDeviceMetadata" in tokens)) {
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
  } else if (tokens.refreshToken) {
    // For fresh logins, we'll still schedule a refresh but with a significant delay
    // This ensures tokens don't expire while the user is active, but doesn't cause
    // immediate refreshes after login
    debug?.("Fresh login detected, deferring token refresh scheduling");

    // Delay scheduling by 2 minutes to avoid multiple refreshes during app initialization
    setTimeout(() => {
      scheduleRefresh({
        abort,
        tokensCb: (newTokens) => {
          if (!newTokens) return;
          return Promise.resolve();
        },
      }).catch((err) => {
        debug?.("Failed to schedule delayed token refresh:", err);
      });
    }, 120000); // 2 minutes delay
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
