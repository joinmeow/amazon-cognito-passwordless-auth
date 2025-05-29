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
import { configure, getTokenEndpoint } from "./config.js";
import { TokensFromRefresh } from "./model.js";
import {
  retrieveTokens,
  storeRefreshScheduleInfo,
  getRefreshScheduleInfo,
} from "./storage.js";
import { getTokensFromRefreshToken, initiateAuth } from "./cognito-api.js";
import { setTimeoutWallClock } from "./util.js";
import { processTokens } from "./common.js";
import { parseJwtPayload } from "./util.js";
import { CognitoAccessTokenPayload } from "./jwt-model.js";

// Simple state tracking
type RefreshState = {
  isRefreshing: boolean;
  refreshTimer?: ReturnType<typeof setTimeoutWallClock>;
  /** Wall-clock timestamp (ms) when the current refreshTimer is scheduled to fire */
  nextRefreshTime?: number;
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
 * Schedule a token refresh so it fires ~5 minutes before expiry
 * (or immediately if expiry is near). Wall-clock timers survive tab sleep.
 */
export async function scheduleRefresh({
  abort,
  tokensCb,
  isRefreshingCb,
}: {
  abort?: AbortSignal;
  tokensCb?: (res: TokensFromRefresh | null) => void | Promise<void>;
  isRefreshingCb?: (isRefreshing: boolean) => unknown;
} = {}): Promise<void> {
  // Skip if already scheduling
  if (refreshState.isRefreshing) {
    logDebug("Token refresh already in progress, skipping");
    return;
  }

  try {
    // Clear any existing timer **only** if the new schedule would fire earlier
    // than the currently scheduled refresh (or if no timer is set).
    const clearExistingTimerIfNeeded = (desiredFireTime: number) => {
      if (
        refreshState.refreshTimer &&
        typeof refreshState.nextRefreshTime === "number" &&
        // If an existing timer will fire *before* (or at the same time as) the
        // desired one, keep it – otherwise cancel and reschedule below.
        refreshState.nextRefreshTime <= desiredFireTime
      ) {
        logDebug(
          `Existing refresh is already scheduled earlier (${new Date(
            refreshState.nextRefreshTime
          ).toISOString()}); skipping reschedule`
        );
        return false; // keep existing timer
      }

      if (refreshState.refreshTimer) {
        refreshState.refreshTimer();
        refreshState.refreshTimer = undefined;
        refreshState.nextRefreshTime = undefined;
      }
      return true; // need to schedule
    };

    // Restore persisted schedule (e.g. after hard reload)
    const persisted = await getRefreshScheduleInfo();
    if (
      !refreshState.refreshTimer &&
      persisted.isScheduled &&
      persisted.expiryTime
    ) {
      const delay = Math.max(
        0,
        persisted.expiryTime - Date.now() - 5 * 60 * 1000
      );
      if (delay > 0) {
        logDebug(
          `Restoring persisted refresh timer to fire in ${Math.round(delay / 1000)}s`
        );
        refreshState.refreshTimer = setTimeoutWallClock(() => {
          void scheduleRefresh({ abort, tokensCb, isRefreshingCb });
        }, delay);
        return;
      }
    }

    // Get current tokens
    const tokens = await retrieveTokens();
    if (abort?.aborted) return;

    if (!tokens?.expireAt) {
      logDebug("No valid tokens found, skipping refresh scheduling");
      // Notify caller that we have no valid tokens
      if (tokensCb) {
        try {
          await tokensCb(null);
        } catch (err) {
          logDebug("Error in tokensCb during no-tokens case:", err);
        }
      }
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
        setTimeoutWallClock(() => {
          void scheduleRefresh({ abort, tokensCb, isRefreshingCb });
        }, 2000);
      } catch (err) {
        logDebug("Failed to refresh token:", err);
      } finally {
        await storeRefreshScheduleInfo({ isScheduled: false });
      }
      return;
    }

    // Standard case: schedule refresh five minutes before expiry
    const refreshDelay = Math.max(0, timeUntilExpiry - 5 * 60 * 1000);

    // After we have determined `refreshDelay`
    const desiredFireTime = Date.now() + refreshDelay;

    // Decide if we actually need to (re-)schedule
    const needToSchedule = clearExistingTimerIfNeeded(desiredFireTime);
    if (!needToSchedule) {
      // Make sure schedule info in storage reflects that a timer is active
      await storeRefreshScheduleInfo({
        isScheduled: true,
        expiryTime: tokenExpiryTime,
      });
      return; // nothing else to do – keep current timer
    }

    // Record scheduling info on the global state *before* creating the timer so
    // concurrent calls have up-to-date information.
    refreshState.nextRefreshTime = desiredFireTime;

    const minutesUntilRefresh = Math.round(refreshDelay / (60 * 1000));
    logDebug(`Scheduling token refresh in ${minutesUntilRefresh} minutes`);

    // Set the timer
    refreshState.refreshTimer = setTimeoutWallClock(async () => {
      // Clear meta as soon as the timer fires (regardless of refresh success)
      refreshState.nextRefreshTime = undefined;
      try {
        await storeRefreshScheduleInfo({ isScheduled: false });

        // Re-read latest token info to avoid stale data
        const latestTokens = await retrieveTokens();

        // Always refresh at the scheduled point – independent of tab visibility
        void refreshTokens({
          abort,
          tokensCb: async (refreshedTokens) => {
            await tokensCb?.(refreshedTokens);
            // Chain the next schedule after successful refresh
            void scheduleRefresh({ abort, tokensCb, isRefreshingCb });
          },
          isRefreshingCb,
          tokens: latestTokens,
        });
      } catch (err) {
        logDebug("Error during scheduled refresh:", err);
        // Try again with backoff
        setTimeoutWallClock(() => {
          void scheduleRefresh({ abort, tokensCb, isRefreshingCb });
        }, 30000); // 30 second backoff
      }
    }, refreshDelay);

    // Handle abort event
    abort?.addEventListener(
      "abort",
      () => {
        if (refreshState.refreshTimer) {
          refreshState.refreshTimer();
          refreshState.refreshTimer = undefined;
          void storeRefreshScheduleInfo({ isScheduled: false });
          logDebug("Refresh scheduling aborted");
        }
      },
      { once: true }
    );
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
  authMethod?: "SRP" | "FIDO2" | "PLAINTEXT" | "REDIRECT";
};

/**
 * Refresh tokens using OAuth token endpoint
 * This handles refresh token rotation in OAuth flows
 */
async function refreshTokensViaOAuth({
  refreshToken,
  abort,
}: {
  refreshToken: string;
  deviceKey?: string;
  abort?: AbortSignal;
}): Promise<{
  accessToken: string;
  idToken?: string;
  refreshToken?: string;
  expiresIn: number;
}> {
  const cfg = configure();
  const { debug, clientId } = cfg;

  debug?.("Using OAuth token endpoint for refresh token flow");

  // Get the OAuth token endpoint
  const tokenEndpoint = getTokenEndpoint();
  debug?.(`Using OAuth token endpoint: ${tokenEndpoint}`);

  // Build the request body for token refresh
  const body = new URLSearchParams({
    grant_type: "refresh_token",
    client_id: clientId,
    refresh_token: refreshToken,
  });

  // Note: Cognito's OAuth2 token endpoint does not accept device_key.
  // Passing unknown parameters can break some proxy/WAF configurations, so we
  // intentionally do NOT send the device key even if we have one.

  debug?.("Sending OAuth token refresh request");

  try {
    const res = await cfg.fetch(tokenEndpoint, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: body.toString(),
      signal: abort,
    });

    if (!res.ok) {
      const errorResponse = await res
        .json()
        .catch(() => ({ error: "Unknown error" }));
      debug?.("OAuth token refresh failed:", errorResponse);
      throw new Error(
        `OAuth token refresh failed: ${
          typeof errorResponse === "object" && errorResponse !== null
            ? "error_description" in errorResponse
              ? String(errorResponse.error_description)
              : "error" in errorResponse
                ? String(errorResponse.error)
                : "Unknown error"
            : "Unknown error"
        }`
      );
    }

    const json = (await res.json()) as {
      access_token: string;
      id_token?: string;
      refresh_token?: string;
      expires_in: number;
      token_type: string;
    };

    debug?.(
      `OAuth token refresh successful - Access token: ${json.access_token ? "present" : "missing"}, ID token: ${json.id_token ? "present" : "missing"}, Refresh token: ${json.refresh_token ? "present" : "missing"}, Expires in: ${json.expires_in}s`
    );

    return {
      accessToken: json.access_token,
      idToken: json.id_token,
      refreshToken: json.refresh_token,
      expiresIn: json.expires_in,
    };
  } catch (error) {
    debug?.(
      "OAuth token refresh error:",
      error instanceof Error ? error.message : String(error)
    );
    throw error;
  }
}

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
  // Shared in-flight guard across tabs (per-user)
  const { clientId, storage } = configure();
  // Determine user identifier (username or sub)
  let userIdentifier: string | undefined = tokens?.username;
  if (!userIdentifier) {
    const storedTokens = await retrieveTokens();
    userIdentifier = storedTokens?.username;
  }
  if (!userIdentifier) {
    throw new Error("Cannot determine user identity for refresh lock");
  }
  const inFlightKey = `Passwordless.${clientId}.${userIdentifier}.refreshTokenInFlight`;
  if (!force) {
    const existing = await storage.getItem(inFlightKey);
    if (existing === "true") {
      logDebug(
        `Token refresh already in progress in another tab for ${userIdentifier}, skipping`
      );
      throw new Error("Token refresh already in progress");
    }
  }
  // Mark as in-flight (shared)
  await storage.setItem(inFlightKey, "true");

  // Prevent concurrent refreshes
  if (refreshState.isRefreshing && !force) {
    logDebug("Token refresh already in progress");
    throw new Error("Token refresh already in progress");
  }

  // Set refreshing state
  refreshState.isRefreshing = true;
  isRefreshingCb?.(true);

  try {
    // Get tokens if not provided
    if (!tokens) {
      tokens = await retrieveTokens();
    }

    // Extract token properties safely
    const refreshToken = tokens?.refreshToken;
    const username = tokens?.username;
    const deviceKey = tokens?.deviceKey;
    const expireAt = tokens?.expireAt;
    const authMethod = tokens?.authMethod;

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
      // Determine refresh approach: OAuth for REDIRECT, else refresh token API or InitiateAuth
      const { debug, useGetTokensFromRefreshToken } = configure();
      let authResult;
      if (authMethod === "REDIRECT") {
        debug?.(
          "Using OAuth token endpoint for refresh since auth method is REDIRECT"
        );
        // OAuth refresh
        const oauthResult = await refreshTokensViaOAuth({
          refreshToken,
          deviceKey,
          abort,
        });
        authResult = {
          AuthenticationResult: {
            AccessToken: oauthResult.accessToken,
            IdToken: oauthResult.idToken,
            RefreshToken: oauthResult.refreshToken,
            ExpiresIn: oauthResult.expiresIn,
            TokenType: "Bearer",
          },
        };
      } else {
        if (useGetTokensFromRefreshToken) {
          debug?.(
            `Using Cognito GetTokensFromRefreshToken API (authMethod: ${authMethod || "unknown"})`
          );
          // Try refresh, retry once on reuse error
          try {
            authResult = await getTokensFromRefreshToken({
              refreshToken,
              deviceKey,
              abort,
            });
          } catch (err) {
            if (
              err instanceof Error &&
              err.name === "RefreshTokenReuseException"
            ) {
              debug?.(
                "Refresh token reuse detected; retrying with latest stored refresh token"
              );
              const latestStored = await retrieveTokens();
              const latestToken = latestStored?.refreshToken;
              if (latestToken && latestToken !== refreshToken) {
                authResult = await getTokensFromRefreshToken({
                  refreshToken: latestToken,
                  deviceKey,
                  abort,
                });
              } else {
                throw err;
              }
            } else {
              throw err;
            }
          }
        } else {
          debug?.("Using InitiateAuth REFRESH_TOKEN flow");
          authResult = await initiateAuth({
            authflow: "REFRESH_TOKEN",
            authParameters: { REFRESH_TOKEN: refreshToken },
            deviceKey,
            abort,
          });
        }
      }

      // Derive a server-authoritative expiry timestamp from the AccessToken's `exp` claim.
      let expireAt: Date;
      try {
        const { exp } = parseJwtPayload<CognitoAccessTokenPayload>(
          authResult.AuthenticationResult.AccessToken
        );
        expireAt = new Date(exp * 1000);
      } catch {
        // Fallback to local clock in case of unexpected token format
        expireAt = new Date(
          Date.now() + authResult.AuthenticationResult.ExpiresIn * 1000
        );
      }

      tokensFromRefresh = {
        accessToken: authResult.AuthenticationResult.AccessToken,
        // idToken is optional in OAuth flows
        ...(authResult.AuthenticationResult.IdToken && {
          idToken: authResult.AuthenticationResult.IdToken,
        }),
        expireAt,
        username,
        // As per AWS docs GetTokensFromRefreshToken always returns a new refresh
        // token when rotation is enabled. We still fall back to the previous
        // value as a safeguard when rotation is disabled.
        refreshToken:
          authResult.AuthenticationResult.RefreshToken ?? refreshToken,
        ...(deviceKey && { deviceKey }),
        // Preserve the authentication method for future refreshes
        ...(authMethod && { authMethod }),
      };

      logDebug(
        `Token refreshed; new refresh token received: ${authResult.AuthenticationResult.RefreshToken ? "yes" : "no"}, expires in ${authResult.AuthenticationResult.ExpiresIn}s`
      );
    } catch (error) {
      logDebug("Token refresh failed:", error);
      throw error;
    }

    // Process tokens
    logDebug(
      `RefreshTokens: old refreshToken=${refreshToken}, new refreshToken=${tokensFromRefresh.refreshToken}`
    );
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
    // Clear shared in-flight flag
    try {
      await storage.removeItem(inFlightKey);
    } catch {
      // ignore errors
    }
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
  const refreshed = await refreshTokens({
    ...(args ?? {}),
    force: true,
  });

  // Resume automatic scheduling after the forced refresh
  void scheduleRefresh();

  return refreshed;
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
