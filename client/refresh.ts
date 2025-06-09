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
import { retrieveTokens } from "./storage.js";
import { getTokensFromRefreshToken, initiateAuth } from "./cognito-api.js";
import { setTimeoutWallClock } from "./util.js";
import { processTokens } from "./common.js";
import { parseJwtPayload } from "./util.js";
import { CognitoAccessTokenPayload } from "./jwt-model.js";
import { withStorageLock } from "./lock.js";

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
  // Debug: visibilitychange event fired
  logDebug(`visibilitychange event: document.hidden=${globalThis.document.hidden}`);
  if (isDocumentVisible()) {
    // If page becomes visible and it's been a while since last refresh,
    // check if we need to schedule a refresh
    const timeThreshold = 60000; // 1 minute
    const lastRefresh = refreshState.lastRefreshTime || 0;
    logDebug(`handleVisibilityChange: lastRefreshTime=${new Date(lastRefresh).toISOString()}`);
    logDebug("handleVisibilityChange: document is visible, evaluating refresh eligibility");

    if (Date.now() - lastRefresh > timeThreshold) {
      logDebug("handleVisibilityChange: threshold passed, scheduling refresh");
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

// Extract original implementation into a helper
async function scheduleRefreshUnlocked({
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
    // Clear any existing timer. The new schedule will always be the single
    // source of truth.
    const clearExistingTimer = () => {
      if (refreshState.refreshTimer) {
        refreshState.refreshTimer();
        refreshState.refreshTimer = undefined;
        refreshState.nextRefreshTime = undefined;
      }
    };
    clearExistingTimer();

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
      logDebug(`scheduleRefreshUnlocked: immediate refresh path, timeUntilExpiry=${timeUntilExpiry}ms`);
      // 60 seconds or less
      logDebug(
        `Token expires in ${Math.round(timeUntilExpiry / 1000)}s, refreshing now`
      );

      try {
        await refreshTokens({
          abort,
          tokensCb,
          isRefreshingCb,
          tokens,
          force: true,
        });

        // After a successful immediate refresh, schedule the next one normally
        // This avoids a tight loop if the refresh somehow fails or returns
        // another short-lived token. We'll rely on the next event (e.g.
        // visibility change) to trigger a new schedule check.
      } catch (err) {
        logDebug("Failed to refresh token:", err);
      }
      return;
    }

    // Standard case: schedule refresh with dynamic buffer based on actual token lifetime
    let refreshDelay: number;

    try {
      // Try to get actual token lifetime from the access token JWT claims
      if (tokens.accessToken) {
        const payload = parseJwtPayload<CognitoAccessTokenPayload>(
          tokens.accessToken
        );
        if (payload.iat && payload.exp) {
          // Calculate actual token lifetime from JWT claims (in seconds, convert to ms)
          const actualLifetime = (payload.exp - payload.iat) * 1000;
          // Use 30% of actual lifetime as buffer, but ensure reasonable bounds
          const bufferTime = Math.max(
            60000, // Minimum 1 minute buffer
            Math.min(
              0.3 * actualLifetime, // 30% of actual lifetime
              15 * 60 * 1000 // Maximum 15 minutes buffer
            )
          );
          refreshDelay = Math.max(0, timeUntilExpiry - bufferTime);
          logDebug(`scheduleRefreshUnlocked dynamic calc: timeUntilExpiry=${timeUntilExpiry}ms, actualLifetime=${actualLifetime}ms, bufferTime=${bufferTime}ms, refreshDelay=${refreshDelay}ms`);
          logDebug(
            `Using dynamic refresh timing: token lifetime=${Math.round(actualLifetime / 60000)}min, ` +
              `buffer=${Math.round(bufferTime / 60000)}min, delay=${Math.round(refreshDelay / 60000)}min`
          );
        } else {
          throw new Error("Missing iat or exp claims");
        }
      } else {
        throw new Error("No access token available");
      }
    } catch (err) {
      // Fallback: use half of remaining time until expiry (previous robust approach)
      refreshDelay = Math.max(0, timeUntilExpiry / 2);
      logDebug(
        `Using fallback refresh timing (half remaining lifetime): delay=${Math.round(refreshDelay / 60000)}min`,
        err
      );
    }

    // After we have determined `refreshDelay`
    const desiredFireTime = Date.now() + refreshDelay;

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
        // Re-read latest token info to avoid stale data
        const latestTokens = await retrieveTokens();

        // Always refresh at the scheduled point – independent of tab visibility
        void refreshTokens({
          abort,
          tokensCb: async (refreshedTokens) => {
            await tokensCb?.(refreshedTokens);
            // After a successful refresh, let the next natural event (like
            // visibility change or watchdog) schedule the subsequent refresh.
            // This prevents tight loops.
          },
          isRefreshingCb,
          tokens: latestTokens,
          force: true,
        });
      } catch (err) {
        logDebug("Error during scheduled refresh:", err);
        // Try again with backoff
        setTimeoutWallClock(() => {
          void scheduleRefreshUnlocked({ abort, tokensCb, isRefreshingCb });
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
          logDebug("Refresh scheduling aborted");
        }
      },
      { once: true }
    );
  } catch (err) {
    logDebug("Error scheduling refresh:", err);
  }
}

// Atomic wrapper with per-user lock
export async function scheduleRefresh(
  args: Parameters<typeof scheduleRefreshUnlocked>[0] = {}
): Promise<void> {
  const { clientId, debug } = configure();
  const tokens0 = await retrieveTokens();
  const userIdentifier = tokens0?.username;
  if (!userIdentifier) {
    // No user found, run unlocked
    debug?.("scheduleRefresh: no user, running unlocked");
    return scheduleRefreshUnlocked(args);
  }

  const lockKey = `Passwordless.${clientId}.${userIdentifier}.refreshLock`;
  // Acquire lock and execute schedule logic
  debug?.("scheduleRefresh: waiting for lock", lockKey);
  const result = await withStorageLock(
    lockKey,
    async () => {
      debug?.("scheduleRefresh: lock acquired", lockKey);
      return scheduleRefreshUnlocked(args);
    },
    undefined,
    args.abort
  );
  debug?.("scheduleRefresh: lock released", lockKey);
  return result;
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
  // Per-user cross-tab lock
  const { clientId } = configure();
  // Determine user identifier (username or sub)
  let userIdentifier: string | undefined = tokens?.username;
  if (!userIdentifier) {
    const storedTokens = await retrieveTokens();
    userIdentifier = storedTokens?.username;
  }
  if (!userIdentifier) {
    throw new Error("Cannot determine user identity for refresh lock");
  }
  const lockKey = `Passwordless.${clientId}.${userIdentifier}.refreshLock`;
  // Internal logic wrapped as a function
  const doRefresh = async (): Promise<TokensFromRefresh> => {
    // Prevent concurrent in-tab refreshes
    if (refreshState.isRefreshing && !force) {
      logDebug("Token refresh already in progress");
      throw new Error("Token refresh already in progress");
    }

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
            // Try refresh, retry once on reuse error or transient network errors
            let lastError: Error | undefined;
            let currentRefreshToken = refreshToken; // Mutable copy for retries
            const maxRetries = 2;

            for (let attempt = 1; attempt <= maxRetries; attempt++) {
              try {
                authResult = await getTokensFromRefreshToken({
                  refreshToken: currentRefreshToken,
                  deviceKey,
                  abort,
                });
                break; // Success, exit retry loop
              } catch (err) {
                lastError = err as Error;

                if (
                  err instanceof Error &&
                  err.name === "RefreshTokenReuseException"
                ) {
                  debug?.(
                    "Refresh token reuse detected; retrying with latest stored refresh token"
                  );
                  const latestStored = await retrieveTokens();
                  const latestToken = latestStored?.refreshToken;
                  if (latestToken && latestToken !== currentRefreshToken) {
                    currentRefreshToken = latestToken; // Update for next attempt
                    continue; // Retry with new token
                  } else {
                    throw err; // No new token available
                  }
                } else if (
                  attempt < maxRetries &&
                  err instanceof Error &&
                  (err.name === "NetworkError" ||
                    err.message.includes("fetch") ||
                    err.message.includes("network") ||
                    err.message.includes("timeout"))
                ) {
                  debug?.(
                    `Transient network error on attempt ${attempt}/${maxRetries}, retrying:`,
                    err.message
                  );
                  // Small delay before retry
                  await new Promise((resolve) =>
                    setTimeout(resolve, 1000 * attempt)
                  );
                  continue;
                } else {
                  throw err; // Non-retryable error or max attempts reached
                }
              }
            }

            if (!authResult) {
              throw (
                lastError || new Error("Failed to refresh tokens after retries")
              );
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
  };
  // Execute with lock, or bypass lock when forcing
  const { debug } = configure();
  if (force) {
    debug?.("refreshTokens: force=true, bypassing lock", lockKey);
    return doRefresh();
  }
  debug?.("refreshTokens: waiting for lock", lockKey);
  const result = await withStorageLock(
    lockKey,
    async () => {
      debug?.("refreshTokens: lock acquired", lockKey);
      return doRefresh();
    },
    undefined,
    abort
  );
  debug?.("refreshTokens: lock released", lockKey);
  return result;
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

  // Force refresh
  const refreshed = await refreshTokens({
    ...(args ?? {}),
    force: true,
  });

  // Resume automatic scheduling after the forced refresh
  void scheduleRefresh({ ...args });

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

  // Listen for window focus to catch resumed tabs or app focus
  // eslint-disable-next-line no-restricted-globals
  globalThis.window.addEventListener("focus", () => {
    // Debug: focus event fired
    logDebug("window focus event fired");
    // Use same throttling as visibility change to prevent rapid fire
    const timeThreshold = 60000; // 1 minute
    const lastRefresh = refreshState.lastRefreshTime || 0;
    logDebug(`focus handler: lastRefreshTime=${new Date(lastRefresh).toISOString()}`);
    if (Date.now() - lastRefresh > timeThreshold) {
      logDebug("focus handler: threshold passed, scheduling refresh");
      void scheduleRefresh();
    }
  });

  // Polling watchdog: re-check every 5 minutes to catch any missed refresh
  // This is a fallback for cases where focus/visibility events are not fired
  const WATCHDOG_INTERVAL_MS = 5 * 60 * 1000;
  const startWatchdog = () => {
    setTimeoutWallClock(() => {
      // Only schedule a refresh if one isn't already pending and if the tab
      // is visible, to avoid unnecessary background work.
      if (!refreshState.refreshTimer && isDocumentVisible()) {
        const lastRefresh = refreshState.lastRefreshTime || 0;
        // Add an extra check to ensure we don't refresh too frequently
        if (Date.now() - lastRefresh > WATCHDOG_INTERVAL_MS) {
          logDebug("Watchdog is triggering a refresh check");
          void scheduleRefresh();
        }
      }
      startWatchdog();
    }, WATCHDOG_INTERVAL_MS);
  };
  startWatchdog();
}
