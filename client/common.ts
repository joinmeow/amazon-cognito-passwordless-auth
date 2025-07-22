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
  getRememberedDevice,
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
import { withStorageLock, LockTimeoutError } from "./lock.js";
import { parseJwtPayload } from "./util.js";
import { CognitoAccessTokenPayload } from "./jwt-model.js";

// Prevent duplicate refresh scheduling within this time window
const REFRESH_DEDUPLICATION_WINDOW_MS = 300000; // 5 minutes

// Delay initial refresh scheduling for fresh logins
const FRESH_LOGIN_REFRESH_DELAY_MS = 120000; // 2 minutes

// Track active refresh schedules to prevent duplicate scheduling
// Key: username, Value: { scheduledAt: timestamp, abortController: AbortController, refreshToken: string }
const activeRefreshSchedules = new Map<
  string,
  {
    scheduledAt: number;
    abortController: AbortController;
    refreshToken: string;
  }
>();

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
 * @returns The processed tokens (with device key and other metadata)
 */
async function processTokensInternal(
  tokens: TokensFromSignIn | TokensFromRefresh,
  abort?: AbortSignal
): Promise<TokensFromSignIn | TokensFromRefresh> {
  const { debug } = configure();

  debug?.("🔄 [Process Tokens] Starting token processing after authentication");

  // Normalize tokens early for consistency
  const normalizedTokens = {
    ...tokens,
    // Ensure idToken is string or undefined, never null or other falsy values
    idToken: tokens.idToken || undefined,
    // Preserve authMethod explicitly
    authMethod: tokens.authMethod,
  } as TokensFromSignIn | TokensFromRefresh;

  // Log token structure to help debug OAuth flows
  debug?.("🔄 [Process Tokens] Processing tokens structure:", {
    hasAccessToken: !!normalizedTokens.accessToken,
    hasIdToken: !!normalizedTokens.idToken,
    hasRefreshToken: !!normalizedTokens.refreshToken,
    hasUsername: !!normalizedTokens.username,
    hasExpireAt: !!normalizedTokens.expireAt,
    hasDeviceKey: !!normalizedTokens.deviceKey,
    authMethod: normalizedTokens.authMethod || "unknown",
    hasNewDeviceMetadata: !!(normalizedTokens as TokensFromSignIn)
      .newDeviceMetadata,
  });

  // 1. Process device confirmation if needed
  if (
    "newDeviceMetadata" in normalizedTokens &&
    normalizedTokens.newDeviceMetadata?.deviceKey
  ) {
    debug?.(
      "🔄 [Process Tokens] Detected new device metadata with device key:",
      normalizedTokens.newDeviceMetadata.deviceKey
    );

    // Complete device confirmation if this is a sign-in (has accessToken)
    if (
      "accessToken" in normalizedTokens &&
      "newDeviceMetadata" in normalizedTokens
    ) {
      // According to AWS docs, we should always confirm a device after successful auth
      // The purpose of device confirmation is to prepare for future MFA bypass,
      // not to require MFA for confirmation
      debug?.(
        "🔄 [Process Tokens] Proceeding with device confirmation after successful authentication"
      );

      try {
        // We can safely cast to TokensFromSignIn here since we've checked for newDeviceMetadata
        // Update normalizedTokens with the result of device confirmation
        Object.assign(
          normalizedTokens,
          await handleDeviceConfirmation(normalizedTokens)
        );
        debug?.(
          "✅ [Process Tokens] Device confirmation completed in processTokens"
        );
      } catch (error) {
        debug?.(
          "❌ [Process Tokens] Error during device confirmation in processTokens:",
          error
        );
      }
    } else {
      debug?.(
        "🔄 [Process Tokens] Setting deviceKey without full device confirmation (no accessToken)"
      );
      // Persist deviceKey for convenience; remembering decision happens later
      await storeDeviceKey(
        normalizedTokens.username,
        normalizedTokens.newDeviceMetadata.deviceKey
      );
    }
  } else if (normalizedTokens.deviceKey) {
    const record = await getRememberedDevice(normalizedTokens.username);
    const remembered = record?.remembered ?? false;
    debug?.(
      `🔄 [Process Tokens] Using existing device key ${normalizedTokens.deviceKey}, remembered: ${remembered}`
    );
  } else {
    debug?.("🔄 [Process Tokens] No device key available in tokens");
  }
  // We only confirm devices when NewDeviceMetadata is provided by Cognito
  // Never attempt to generate a device key or confirm without explicit metadata

  // 2. Store tokens for persistence
  debug?.("🔄 [Process Tokens] Storing tokens for persistence");

  // Store the already normalized tokens
  await storeTokens(normalizedTokens);
  debug?.("🔄 [Process Tokens] After storeTokens, tokens:", {
    hasAccessToken: !!normalizedTokens.accessToken,
    hasIdToken: !!normalizedTokens.idToken,
    hasRefreshToken: !!normalizedTokens.refreshToken,
    username: normalizedTokens.username,
    expiresAt: normalizedTokens.expireAt?.toISOString(),
  });

  // 3. Schedule refresh if we have a refresh token
  // But only if this is NOT a fresh login (indicated by newDeviceMetadata)
  // This prevents immediate refresh scheduling right after login
  if (normalizedTokens.refreshToken && normalizedTokens.username) {
    // Check if we already have an active schedule for this user
    const existingSchedule = activeRefreshSchedules.get(
      normalizedTokens.username
    );
    const now = Date.now();

    // Skip if we already scheduled for this user recently (within 5 minutes)
    if (
      existingSchedule &&
      now - existingSchedule.scheduledAt < REFRESH_DEDUPLICATION_WINDOW_MS
    ) {
      debug?.(
        "🔄 [Process Tokens] Refresh already scheduled for this user, skipping duplicate"
      );
      return normalizedTokens;
    }

    // Clear any existing schedule for this user
    if (existingSchedule?.abortController) {
      existingSchedule.abortController.abort();
      activeRefreshSchedules.delete(normalizedTokens.username);
    }

    const scheduleAbort = new AbortController();

    // Connect external abort signal to our schedule abort controller
    if (abort) {
      abort.addEventListener(
        "abort",
        () => {
          scheduleAbort.abort();
          // Clean up the schedule tracking when aborted
          if (normalizedTokens.username) {
            activeRefreshSchedules.delete(normalizedTokens.username);
          }
        },
        { once: true }
      );
    }

    // Track this schedule to prevent duplicates
    activeRefreshSchedules.set(normalizedTokens.username, {
      scheduledAt: now,
      abortController: scheduleAbort,
      refreshToken: normalizedTokens.refreshToken,
    });

    const scheduleFn = () => {
      debug?.("🔄 [Process Tokens] Scheduling token refresh");
      scheduleRefresh({
        abort: scheduleAbort.signal,
        tokensCb: (newTokens) => {
          // Always clear the schedule tracking when refresh completes (success or no tokens)
          if (normalizedTokens.username) {
            activeRefreshSchedules.delete(normalizedTokens.username);
          }
          if (!newTokens) return;
          // We don't need to store tokens here because processTokens will be called
          // for the refresh tokens too, and it will store them.
          return Promise.resolve();
        },
      }).catch((err) => {
        debug?.("❌ [Process Tokens] Failed to schedule token refresh:", err);
        // Clear the schedule tracking on error
        if (normalizedTokens.username) {
          activeRefreshSchedules.delete(normalizedTokens.username);
        }
      });
    };

    if (!("newDeviceMetadata" in normalizedTokens)) {
      // Not a fresh login, schedule immediately
      scheduleFn();
    } else {
      // Fresh login, delay by 2 minutes
      debug?.(
        "🔄 [Process Tokens] Fresh login detected, deferring token refresh scheduling"
      );
      setTimeout(scheduleFn, FRESH_LOGIN_REFRESH_DELAY_MS);
    }
  } else {
    debug?.(
      "🔄 [Process Tokens] No refresh token available, skipping refresh scheduling"
    );
  }

  debug?.("✅ [Process Tokens] Token processing completed successfully");
  return normalizedTokens;
}

/**
 * Process tokens with storage lock protection to prevent race conditions
 * in multi-tab/multi-process scenarios.
 */
export async function processTokens(
  tokens: TokensFromSignIn | TokensFromRefresh,
  abort?: AbortSignal
): Promise<TokensFromSignIn | TokensFromRefresh> {
  const { clientId, debug } = configure();

  // Extract username for lock key
  let username = tokens.username;
  if (!username) {
    // Parse from access token if not provided
    try {
      const accessPayload = parseJwtPayload<CognitoAccessTokenPayload>(
        tokens.accessToken
      );
      username = accessPayload.username;
    } catch (error) {
      debug?.("Failed to parse username from access token:", error);
      // Continue to throw the more specific error below
    }
  }

  if (!username) {
    throw new Error("Could not determine username for processTokens lock");
  }

  const lockKey = `Passwordless.${clientId}.${username}.authLock`;

  debug?.("🔒 [Process Tokens] Acquiring auth lock for user:", username);

  try {
    return await withStorageLock(
      lockKey,
      async () => processTokensInternal(tokens, abort),
      undefined, // use default timeout
      abort
    );
  } catch (error) {
    if (error instanceof LockTimeoutError) {
      debug?.(
        "⏱️ [Process Tokens] Lock timeout - another auth operation in progress"
      );
      throw new Error(
        "Another authentication operation is in progress. Please try again."
      );
    }
    throw error;
  }
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

  // Wrap sign-out in per-user storage lock
  const signedOut = (async () => {
    // Determine lock key per user
    const tokens0 = await retrieveTokens();
    const userIdentifier = tokens0?.username;
    const lockKey = userIdentifier
      ? `Passwordless.${clientId}.${userIdentifier}.refreshLock`
      : undefined;
    // Run sign-out logic under lock if we have a user
    const doSignOut = async () => {
      try {
        debug?.("signOut: performing sign-out for user", userIdentifier);

        // Clean up any active refresh schedules for this user
        if (userIdentifier) {
          const activeSchedule = activeRefreshSchedules.get(userIdentifier);
          if (activeSchedule) {
            debug?.("signOut: cancelling active refresh schedule for user");
            activeSchedule.abortController.abort();
            activeRefreshSchedules.delete(userIdentifier);
          }
        }

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
      } catch (error) {
        if (abort.signal.aborted) return;
        debug?.("Error during sign-out:", error);
        currentStatus && statusCb?.(currentStatus);
        throw error;
      }
    };
    if (lockKey) {
      debug?.("signOut: waiting for lock", lockKey);
      const result = await withStorageLock(
        lockKey,
        async () => {
          debug?.("signOut: lock acquired", lockKey);
          return doSignOut();
        },
        undefined,
        abort.signal
      );
      debug?.("signOut: lock released", lockKey);
      return result;
    }
    debug?.("signOut: no lock key, running unlocked");
    return doSignOut();
  })();
  return {
    signedOut,
    abort: () => abort.abort(),
  };
};
