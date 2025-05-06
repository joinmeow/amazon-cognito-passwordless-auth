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
import { configure } from "./config.js";
import { TokensFromRefresh } from "./model.js";
import {
  retrieveTokens,
  TokensFromStorage,
  storeRefreshScheduleInfo,
  getRefreshScheduleInfo,
} from "./storage.js";
import { initiateAuth, getTokensFromRefreshToken } from "./cognito-api.js";
import { setTimeoutWallClock } from "./util.js";
import { processTokens } from "./common.js";

let schedulingRefresh: ReturnType<typeof _scheduleRefresh> | undefined =
  undefined;
export async function scheduleRefresh(
  ...args: Parameters<typeof _scheduleRefresh>
) {
  const { debug } = configure();

  // Skip scheduling if already in progress
  if (schedulingRefresh) {
    debug?.(
      "Refresh scheduling already in progress, returning existing promise"
    );
    return schedulingRefresh;
  }

  schedulingRefresh = _scheduleRefresh(...args).finally(
    () => (schedulingRefresh = undefined)
  );

  return schedulingRefresh;
}

type TokensForRefresh = Partial<
  Pick<
    TokensFromStorage,
    "refreshToken" | "expireAt" | "username" | "deviceKey"
  >
>;

let clearScheduledRefresh: ReturnType<typeof setTimeoutWallClock> | undefined =
  undefined;
async function _scheduleRefresh({
  abort,
  tokensCb,
  isRefreshingCb,
}: {
  abort?: AbortSignal;
  tokensCb?: (res: TokensFromRefresh) => void | Promise<void>;
  isRefreshingCb?: (isRefreshing: boolean) => unknown;
}) {
  const { debug } = configure();

  // Clean up any existing scheduled refresh
  if (clearScheduledRefresh) {
    clearScheduledRefresh();
    clearScheduledRefresh = undefined;
    // Clear the scheduled state to make sure we're in a clean state
    await storeRefreshScheduleInfo({ isScheduled: false });
  }

  // Get current tokens
  const tokens = await retrieveTokens();
  if (abort?.aborted) return;

  if (!tokens?.expireAt) {
    debug?.(
      "No valid tokens or expiry time found, skipping refresh scheduling"
    );
    return;
  }

  const tokenExpiryTime = tokens.expireAt.valueOf();

  // Check if a refresh is already scheduled for this token expiry (or a more recent one)
  const { isScheduled, expiryTime } = await getRefreshScheduleInfo();
  if (isScheduled && expiryTime && expiryTime >= tokenExpiryTime) {
    debug?.(
      "A refresh is already scheduled for this token expiry or later, skipping"
    );
    return;
  }

  // Refresh 60 seconds before expiry
  // Add some jitter, to spread scheduled refreshes
  const refreshIn = Math.max(
    0,
    tokenExpiryTime -
      Date.now() -
      // Base refresh time: 60 seconds before expiry
      60 * 1000 -
      // Add jitter of ±15 seconds to prevent thundering herd
      (Math.random() * 30 - 15) * 1000
  );

  // Calculate token lifetime in minutes for better logging
  const tokenLifetimeMinutes = Math.round(
    (tokenExpiryTime - Date.now()) / (60 * 1000)
  );

  // Only schedule refresh if tokens will expire in more than 5 minutes
  // This avoids refreshing tokens that were just obtained
  if (refreshIn >= 300000) {
    // 5 minutes in milliseconds
    debug?.(
      `Scheduling refresh for token that expires in ${tokenLifetimeMinutes} minutes (refresh in ${Math.round(refreshIn / 1000)} seconds)`
    );

    // Mark that we have a refresh scheduled
    await storeRefreshScheduleInfo({
      isScheduled: true,
      expiryTime: tokenExpiryTime,
    });

    clearScheduledRefresh = setTimeoutWallClock(() => {
      // When this runs, we no longer have a scheduled refresh
      (async () => {
        // Update the scheduled state in storage
        await storeRefreshScheduleInfo({ isScheduled: false });

        refreshTokens({
          abort,
          tokensCb: async (refreshedTokens) => {
            // Check if we have a new refresh token (refresh token rotation)
            if (
              refreshedTokens.refreshToken &&
              refreshedTokens.refreshToken !== tokens?.refreshToken
            ) {
              debug?.("Refresh token has been rotated with a new token");
            }

            // Call the original tokensCb if provided
            await tokensCb?.(refreshedTokens);

            // Schedule the next refresh
            scheduleRefresh({
              abort,
              tokensCb,
              isRefreshingCb,
            }).catch((err) => debug?.("Failed to schedule next refresh:", err));
          },
          isRefreshingCb,
          tokens,
        }).catch((err) => {
          debug?.("Failed to refresh tokens:", err);

          // Get a backoff time based on token expiry time
          // If tokens expire soon, retry quickly (within 30 sec)
          // If tokens expire later, we can wait longer
          const tokenExpiryTime = tokens?.expireAt?.valueOf() ?? 0;
          const timeUntilExpiry = Math.max(0, tokenExpiryTime - Date.now());

          // Backoff time: min 5 seconds, max 5 minutes, based on 10% of time until expiry
          const backoffMs = Math.min(
            300000, // 5 min max
            Math.max(
              5000, // 5 sec min
              timeUntilExpiry * 0.1 // 10% of remaining time
            )
          );

          debug?.(
            `Will retry refresh after backoff of ${Math.round(backoffMs / 1000)} seconds`
          );

          // Schedule retry with backoff
          setTimeout(() => {
            // Even if refresh failed, we should still try to schedule next refresh
            scheduleRefresh({
              abort,
              tokensCb,
              isRefreshingCb,
            }).catch((err) =>
              debug?.("Failed to schedule next refresh after error:", err)
            );
          }, backoffMs);
        });
      })().catch((err) => debug?.("Error updating refresh state:", err));
    }, refreshIn);

    abort?.addEventListener("abort", () => {
      if (clearScheduledRefresh) {
        clearScheduledRefresh();
        clearScheduledRefresh = undefined;

        // Make sure to update the scheduled state when aborted
        storeRefreshScheduleInfo({ isScheduled: false }).catch((err) =>
          debug?.("Error clearing refresh state on abort:", err)
        );

        debug?.("Refresh scheduling aborted");
      }
    });
  } else if (refreshIn > 0 && refreshIn < 30000) {
    // If less than 30 seconds until expiry but more than 0
    // Refresh immediately to prevent token expiration
    debug?.(
      `Token expires in ${Math.round(refreshIn / 1000)} seconds - refreshing immediately`
    );

    await storeRefreshScheduleInfo({
      isScheduled: true,
      expiryTime: tokenExpiryTime,
    });

    // Start immediate refresh
    refreshTokens({
      abort,
      tokensCb,
      isRefreshingCb,
      tokens,
    })
      .then((refreshedTokens) => {
        debug?.("Successfully refreshed token that was about to expire");
        return refreshedTokens;
      })
      .catch((err) => {
        debug?.("Failed to refresh token that was about to expire:", err);
        // If the token is very close to expiry (< 10 seconds), warn about potential auth issues
        if (refreshIn < 10000) {
          debug?.("WARNING: Token may expire before next refresh attempt");
        }
      })
      .finally(() => {
        // Make sure to update the scheduled state when finished
        storeRefreshScheduleInfo({ isScheduled: false }).catch((err) =>
          debug?.("Error clearing refresh state after immediate refresh:", err)
        );
      });
  } else if (refreshIn <= 0) {
    debug?.("Token already expired, not scheduling refresh");
  } else {
    debug?.(
      `Token expires in ${tokenLifetimeMinutes} minutes but was recently obtained, not scheduling refresh yet`
    );
  }

  return clearScheduledRefresh;
}

let refreshingTokens: ReturnType<typeof _refreshTokens> | undefined = undefined;
export async function refreshTokens(
  ...args: Parameters<typeof _refreshTokens>
) {
  // If already refreshing, return the existing promise
  if (refreshingTokens) {
    return refreshingTokens;
  }

  refreshingTokens = _refreshTokens(...args).finally(
    () => (refreshingTokens = undefined)
  );

  return refreshingTokens;
}

// Maintain a set of failed refresh tokens to avoid retrying them
// We include a max size and timestamps for cleanup
const invalidRefreshTokens = new Map<string, number>();
const MAX_INVALID_TOKENS = 100;

async function _refreshTokens({
  abort,
  tokensCb,
  isRefreshingCb,
  tokens,
}: {
  abort?: AbortSignal;
  tokensCb?: (res: TokensFromRefresh) => void | Promise<void>;
  isRefreshingCb?: (isRefreshing: boolean) => unknown;
  tokens?: TokensForRefresh;
}): Promise<TokensFromRefresh> {
  isRefreshingCb?.(true);
  try {
    const { debug, useGetTokensFromRefreshToken } = configure();
    if (!tokens) {
      tokens = await retrieveTokens();
    }
    const { refreshToken, username, deviceKey } = tokens ?? {};
    if (!refreshToken || !username) {
      throw new Error("Cannot refresh without refresh token and username");
    }

    // Check if this token has failed previously
    if (invalidRefreshTokens.has(refreshToken)) {
      const errorMessage = `Will not attempt refresh using token that failed previously: ${refreshToken.substring(0, 10)}...`;
      debug?.(errorMessage);
      throw new Error(errorMessage);
    }

    // Periodically clean up old invalid tokens
    if (invalidRefreshTokens.size > MAX_INVALID_TOKENS) {
      debug?.("Cleaning up invalid refresh token cache");
      const now = Date.now();
      // Clean tokens older than 1 hour
      const ONE_HOUR = 60 * 60 * 1000;
      for (const [token, timestamp] of invalidRefreshTokens.entries()) {
        if (now - timestamp > ONE_HOUR) {
          invalidRefreshTokens.delete(token);
        }
      }
    }

    debug?.(
      `Refreshing tokens using refresh token (using ${useGetTokensFromRefreshToken ? "GetTokensFromRefreshToken" : "InitiateAuth"})...`
    );

    // Always include device key if available - AWS documentation indicates device keys
    // should be included in all auth flows if available
    let useDeviceKey: string | undefined = undefined;
    if (deviceKey) {
      debug?.("Including device key in refresh token flow");
      useDeviceKey = deviceKey;
    }

    let tokensFromRefresh: TokensFromRefresh;

    if (useGetTokensFromRefreshToken) {
      // Use the new GetTokensFromRefreshToken API
      const authResult = await getTokensFromRefreshToken({
        refreshToken,
        deviceKey: useDeviceKey,
        abort,
      }).catch((err) => {
        invalidRefreshTokens.set(refreshToken, Date.now());
        throw err;
      });

      // Create token response with username
      tokensFromRefresh = {
        accessToken: authResult.AuthenticationResult.AccessToken,
        idToken: authResult.AuthenticationResult.IdToken,
        expireAt: new Date(
          Date.now() + authResult.AuthenticationResult.ExpiresIn * 1000
        ),
        username,
        // Include refreshToken if provided in the response (refresh token rotation)
        ...(authResult.AuthenticationResult.RefreshToken && {
          refreshToken: authResult.AuthenticationResult.RefreshToken,
        }),
        // Always include the device key if available (consistent with AWS docs)
        ...(useDeviceKey && { deviceKey: useDeviceKey }),
      };
    } else {
      // Use the legacy InitiateAuth with REFRESH_TOKEN flow
      const authParameters: Record<string, string> = {
        REFRESH_TOKEN: refreshToken,
      };

      // Add device key to auth parameters if available
      if (useDeviceKey) {
        authParameters.DEVICE_KEY = useDeviceKey;
      }

      const authResult = await initiateAuth({
        authflow: "REFRESH_TOKEN",
        authParameters,
        deviceKey: useDeviceKey,
        abort,
      }).catch((err) => {
        invalidRefreshTokens.set(refreshToken, Date.now());
        throw err;
      });

      // Create token response with username
      tokensFromRefresh = {
        accessToken: authResult.AuthenticationResult.AccessToken,
        idToken: authResult.AuthenticationResult.IdToken,
        expireAt: new Date(
          Date.now() + authResult.AuthenticationResult.ExpiresIn * 1000
        ),
        username,
        // Always include the device key if available (consistent with AWS docs)
        ...(useDeviceKey && { deviceKey: useDeviceKey }),
      };
    }

    // First process tokens to handle storage and device confirmation
    const processedTokens = await processTokens(tokensFromRefresh, abort);

    // Then invoke the callback if provided
    if (tokensCb) {
      await tokensCb(processedTokens as TokensFromRefresh);
    }

    return processedTokens as TokensFromRefresh;
  } finally {
    isRefreshingCb?.(false);
  }
}
