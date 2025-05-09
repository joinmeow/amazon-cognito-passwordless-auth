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
import { retrieveTokens, storeRefreshScheduleInfo } from "./storage.js";
import { initiateAuth, getTokensFromRefreshToken } from "./cognito-api.js";
import { setTimeoutWallClock } from "./util.js";
import { processTokens } from "./common.js";

// Simple state tracking
type RefreshState = {
  isRefreshing: boolean;
  refreshTimer?: ReturnType<typeof setTimeoutWallClock>;
  lastRefreshTime?: number;
};

const refreshState: RefreshState = {
  isRefreshing: false,
};

// Basic browser environment detection
function isBrowserEnvironment(): boolean {
  return (
    typeof globalThis !== "undefined" &&
    typeof globalThis.document !== "undefined"
  );
}

// Simplified document visibility check
function isDocumentVisible(): boolean {
  if (!isBrowserEnvironment()) return true;
  return !globalThis.document.hidden;
}

// Handle visibility change for browser environments
function handleVisibilityChange() {
  if (isDocumentVisible()) {
    // If page becomes visible and it's been a while since last refresh,
    // check if we need to schedule a refresh
    const timeThreshold = 60000; // 1 minute
    const lastRefresh = refreshState.lastRefreshTime || 0;

    if (Date.now() - lastRefresh > timeThreshold) {
      void scheduleRefresh();
    }
  }
}

// Simple debug helper
function logDebug(message: string, error?: unknown): void {
  const { debug } = configure();
  if (!debug) return;

  if (error) {
    const errorMsg = error instanceof Error ? error.message : String(error);
    debug(message, errorMsg);
  } else {
    debug(message);
  }
}

/**
 * Schedule a token refresh based on token expiry
 * Using a simple approach: refresh at 75% of token lifetime
 */
export async function scheduleRefresh({
  abort,
  tokensCb,
  isRefreshingCb,
}: {
  abort?: AbortSignal;
  tokensCb?: (res: TokensFromRefresh) => void | Promise<void>;
  isRefreshingCb?: (isRefreshing: boolean) => unknown;
} = {}): Promise<void> {
  // Skip if already scheduling
  if (refreshState.isRefreshing) {
    logDebug("Token refresh already in progress, skipping");
    return;
  }

  try {
    // Clear any existing timer
    if (refreshState.refreshTimer) {
      refreshState.refreshTimer();
      refreshState.refreshTimer = undefined;
      await storeRefreshScheduleInfo({ isScheduled: false });
    }

    // Get current tokens
    const tokens = await retrieveTokens();
    if (abort?.aborted) return;

    if (!tokens?.expireAt) {
      logDebug("No valid tokens found, skipping refresh scheduling");
      return;
    }

    const tokenExpiryTime = tokens.expireAt.valueOf();
    const currentTime = Date.now();
    const timeUntilExpiry = tokenExpiryTime - currentTime;

    // If token is already expired or expires very soon, refresh immediately
    if (timeUntilExpiry <= 60000) {
      // 60 seconds or less
      logDebug(
        `Token expires in ${Math.round(timeUntilExpiry / 1000)}s, refreshing now`
      );

      try {
        // Mark as scheduled while we refresh
        await storeRefreshScheduleInfo({
          isScheduled: true,
          expiryTime: tokenExpiryTime,
        });

        await refreshTokens({
          abort,
          tokensCb,
          isRefreshingCb,
          tokens,
        });

        // Schedule next refresh with a small delay to avoid race conditions
        setTimeout(() => {
          void scheduleRefresh({ abort, tokensCb, isRefreshingCb });
        }, 2000);
      } catch (err) {
        logDebug("Failed to refresh token:", err);
      } finally {
        await storeRefreshScheduleInfo({ isScheduled: false });
      }
      return;
    }

    // Standard case: Schedule refresh at 50% of remaining token lifetime (half-time)
    // This provides more frequent refreshes for better token freshness
    const refreshDelay = Math.max(0, timeUntilExpiry * 0.5);

    // Record scheduling info
    await storeRefreshScheduleInfo({
      isScheduled: true,
      expiryTime: tokenExpiryTime,
    });

    const minutesUntilRefresh = Math.round(refreshDelay / (60 * 1000));
    logDebug(`Scheduling token refresh in ${minutesUntilRefresh} minutes`);

    // Set the timer
    refreshState.refreshTimer = setTimeoutWallClock(async () => {
      try {
        await storeRefreshScheduleInfo({ isScheduled: false });

        // Only refresh if document is visible or close to expiry
        if (isDocumentVisible() || timeUntilExpiry < 5 * 60 * 1000) {
          void refreshTokens({
            abort,
            tokensCb: async (refreshedTokens) => {
              await tokensCb?.(refreshedTokens);
              // Schedule the next refresh
              void scheduleRefresh({ abort, tokensCb, isRefreshingCb });
            },
            isRefreshingCb,
            tokens,
          });
        } else {
          logDebug("Page not visible, deferring refresh");
          // Schedule a check soon to see if page becomes visible
          setTimeout(() => {
            void scheduleRefresh({ abort, tokensCb, isRefreshingCb });
          }, 60000); // Check again in 1 minute
        }
      } catch (err) {
        logDebug("Error during scheduled refresh:", err);
        // Try again with backoff
        setTimeout(() => {
          void scheduleRefresh({ abort, tokensCb, isRefreshingCb });
        }, 30000); // 30 second backoff
      }
    }, refreshDelay);

    // Handle abort event
    abort?.addEventListener("abort", () => {
      if (refreshState.refreshTimer) {
        refreshState.refreshTimer();
        refreshState.refreshTimer = undefined;
        void storeRefreshScheduleInfo({ isScheduled: false });
        logDebug("Refresh scheduling aborted");
      }
    });
  } catch (err) {
    logDebug("Error scheduling refresh:", err);
  }
}

/**
 * Token types and interfaces
 */
type TokenPayload = {
  refreshToken?: string;
  accessToken?: string;
  username?: string;
  deviceKey?: string;
  expireAt?: Date;
};

/**
 * Refresh tokens using the refresh token
 * Uses a simplified approach with basic retry
 */
export async function refreshTokens({
  abort,
  tokensCb,
  isRefreshingCb,
  tokens,
  force = false,
}: {
  abort?: AbortSignal;
  tokensCb?: (res: TokensFromRefresh) => void | Promise<void>;
  isRefreshingCb?: (isRefreshing: boolean) => unknown;
  tokens?: TokenPayload;
  force?: boolean;
} = {}): Promise<TokensFromRefresh> {
  // Prevent concurrent refreshes
  if (refreshState.isRefreshing && !force) {
    logDebug("Token refresh already in progress");
    throw new Error("Token refresh already in progress");
  }

  // Set refreshing state
  refreshState.isRefreshing = true;
  isRefreshingCb?.(true);

  try {
    const { useGetTokensFromRefreshToken } = configure();

    // Get tokens if not provided
    if (!tokens) {
      tokens = await retrieveTokens();
    }

    // Extract token properties safely
    const refreshToken = tokens?.refreshToken;
    const username = tokens?.username;
    const deviceKey = tokens?.deviceKey;
    const expireAt = tokens?.expireAt;

    // Basic validation
    if (!refreshToken || !username) {
      throw new Error("Cannot refresh without refresh token and username");
    }

    // Log refresh attempt
    if (expireAt) {
      const timeUntilExpiry = expireAt.valueOf() - Date.now();
      if (timeUntilExpiry > 0) {
        logDebug(
          force
            ? `Force refreshing token that expires in ${Math.round(timeUntilExpiry / 1000)}s`
            : `Refreshing token (at half expiration time) that expires in ${Math.round(timeUntilExpiry / 1000)}s`
        );
      } else {
        logDebug(
          `Refreshing expired token (${Math.abs(Math.round(timeUntilExpiry / 1000))}s ago)`
        );
      }
    }

    // Perform the token refresh
    let tokensFromRefresh: TokensFromRefresh;

    try {
      if (useGetTokensFromRefreshToken) {
        // Use new GetTokensFromRefreshToken API
        const authResult = await getTokensFromRefreshToken({
          refreshToken,
          deviceKey,
          abort,
        });

        tokensFromRefresh = {
          accessToken: authResult.AuthenticationResult.AccessToken,
          idToken: authResult.AuthenticationResult.IdToken,
          expireAt: new Date(
            Date.now() + authResult.AuthenticationResult.ExpiresIn * 1000
          ),
          username,
          ...(authResult.AuthenticationResult.RefreshToken && {
            refreshToken: authResult.AuthenticationResult.RefreshToken,
          }),
          ...(deviceKey && { deviceKey }),
        };

        logDebug(
          `Token refreshed, expires in ${authResult.AuthenticationResult.ExpiresIn}s`
        );
      } else {
        // Use legacy InitiateAuth flow
        const authParameters: Record<string, string> = {
          REFRESH_TOKEN: refreshToken,
        };

        if (deviceKey) {
          authParameters.DEVICE_KEY = deviceKey;
        }

        const authResult = await initiateAuth({
          authflow: "REFRESH_TOKEN",
          authParameters,
          deviceKey,
          abort,
        });

        tokensFromRefresh = {
          accessToken: authResult.AuthenticationResult.AccessToken,
          idToken: authResult.AuthenticationResult.IdToken,
          expireAt: new Date(
            Date.now() + authResult.AuthenticationResult.ExpiresIn * 1000
          ),
          username,
          ...(deviceKey && { deviceKey }),
        };

        logDebug(
          `Token refreshed, expires in ${authResult.AuthenticationResult.ExpiresIn}s`
        );
      }
    } catch (error) {
      logDebug("Token refresh failed:", error);
      throw error;
    }

    // Process tokens
    const processedTokens = await processTokens(tokensFromRefresh, abort);

    // Reset schedule info
    await storeRefreshScheduleInfo({ isScheduled: false });

    // Update last refresh time
    refreshState.lastRefreshTime = Date.now();

    // Invoke callback
    if (tokensCb) {
      await tokensCb(processedTokens as TokensFromRefresh);
    }

    return processedTokens as TokensFromRefresh;
  } finally {
    refreshState.isRefreshing = false;
    isRefreshingCb?.(false);
  }
}

/**
 * Force an immediate token refresh
 */
export async function forceRefreshTokens(
  args?: Omit<Parameters<typeof refreshTokens>[0], "force">
): Promise<TokensFromRefresh> {
  logDebug("Forcing immediate token refresh");

  // Clear any scheduled refresh
  if (refreshState.refreshTimer) {
    refreshState.refreshTimer();
    refreshState.refreshTimer = undefined;
  }

  // Clear schedule info
  try {
    await storeRefreshScheduleInfo({ isScheduled: false });
  } catch (err) {
    logDebug("Error clearing refresh schedule info:", err);
  }

  // Force refresh
  return refreshTokens({
    ...args,
    force: true,
  });
}

// Initialize visibility change listener for browser environments
if (isBrowserEnvironment()) {
  // Add the event listener with eslint exception for document global
  // eslint-disable-next-line no-restricted-globals
  globalThis.document.addEventListener(
    "visibilitychange",
    handleVisibilityChange
  );
}
