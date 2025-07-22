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
import { retrieveTokens, retrieveTokensForRefresh } from "./storage.js";
import { getTokensFromRefreshToken, initiateAuth } from "./cognito-api.js";
import { setTimeoutWallClock } from "./util.js";
import { processTokens } from "./common.js";
import { parseJwtPayload } from "./util.js";
import { CognitoAccessTokenPayload } from "./jwt-model.js";
import { withStorageLock, LockTimeoutError } from "./lock.js";

// Simple state tracking
type RefreshState = {
  isRefreshing: boolean;
  refreshTimer?: ReturnType<typeof setTimeoutWallClock>;
  /** Wall-clock timestamp (ms) when the current refreshTimer is scheduled to fire */
  nextRefreshTime?: number;
  lastRefreshTime?: number;
  /** Timer for delayed visibility change handling */
  visibilityTimer?: ReturnType<typeof setTimeout>;
};

// Per-user refresh state to prevent conflicts
const refreshStateMap = new Map<string, RefreshState>();

// Get or create refresh state for a user
function getRefreshState(username?: string): RefreshState {
  if (!username) {
    // For operations without a username (like initial page load),
    // create a temporary state that won't interfere with user-specific states
    return { isRefreshing: false };
  }
  
  let state = refreshStateMap.get(username);
  if (!state) {
    state = { isRefreshing: false };
    refreshStateMap.set(username, state);
  }
  return state;
}

// Clear refresh state for a user
function clearRefreshState(username?: string): void {
  const key = username || "default";
  refreshStateMap.delete(key);
}

// Track cleanup functions
let watchdogCleanup: (() => void) | undefined;
let visibilityChangeListener: (() => void) | undefined;

// Max consecutive refresh failures before giving up
const MAX_CONSECUTIVE_REFRESH_FAILURES = 5;
let consecutiveRefreshFailures = 0;

// Generate unique tab ID for this tab
const TAB_ID =
  typeof globalThis.crypto !== "undefined" && globalThis.crypto.randomUUID
    ? globalThis.crypto.randomUUID()
    : `${Date.now()}-${Math.random().toString(36).substring(2, 11)}`;

/**
 * Refresh coordination using a probabilistic approach with timestamp tracking
 *
 * Since localStorage doesn't provide atomic operations, we use a combination of:
 * 1. Timestamp-based coordination to prevent refresh storms
 * 2. Random jitter to reduce collision probability
 * 3. Simple last-write-wins semantics
 */
async function shouldAttemptRefresh(): Promise<boolean> {
  try {
    const { storage, clientId } = configure();
    const tokens = await retrieveTokens();
    if (!tokens?.username) return false;

    const attemptKey = `Passwordless.${clientId}.${tokens.username}.lastRefreshAttempt`;
    const REFRESH_WINDOW_MS = 5000; // Don't refresh if another tab did within 5s
    const RANDOM_JITTER_MAX_MS = 1000; // Increased to 1 second for better collision avoidance

    // Add random jitter to reduce collision probability
    const jitter = Math.floor(Math.random() * RANDOM_JITTER_MAX_MS);
    await new Promise((resolve) => setTimeout(resolve, jitter));

    const now = Date.now();

    // Check if another tab recently attempted refresh
    const lastAttemptValue = await storage.getItem(attemptKey);
    if (lastAttemptValue) {
      // Parse the timestamp, handling various formats for robustness
      let lastAttemptTime: number | null = null;

      // Try parsing as "timestamp:tabId" format
      const match = lastAttemptValue.match(/^(\d+):/);
      if (match) {
        lastAttemptTime = parseInt(match[1], 10);
      } else if (/^\d+$/.test(lastAttemptValue)) {
        // Fallback: plain timestamp
        lastAttemptTime = parseInt(lastAttemptValue, 10);
      }

      // Check if the last attempt is recent and valid
      if (lastAttemptTime && !isNaN(lastAttemptTime)) {
        const timeSinceLastAttempt = now - lastAttemptTime;

        if (timeSinceLastAttempt < REFRESH_WINDOW_MS) {
          logDebug(
            `Another tab attempted refresh ${timeSinceLastAttempt}ms ago, skipping`
          );
          return false;
        }
      }
      // If we can't parse the value, treat it as stale and proceed
    }

    // Record our attempt timestamp
    // We don't need to verify this write succeeded - if multiple tabs write
    // at the same time, that's okay as long as they all see a recent timestamp
    const ourValue = `${now}:${TAB_ID}`;
    await storage.setItem(attemptKey, ourValue);

    logDebug(`Tab ${TAB_ID} proceeding with refresh attempt`);
    return true;
  } catch (err) {
    // If storage fails, don't attempt refresh to avoid uncoordinated refreshes
    logDebug("Error checking refresh coordination, skipping refresh:", err);
    return false;
  }
}

/**
 * Clear the refresh attempt lock after successful refresh
 */
async function clearRefreshAttemptLock(): Promise<void> {
  try {
    const { storage, clientId } = configure();
    const tokens = await retrieveTokens();
    if (!tokens?.username) return;

    const attemptKey = `Passwordless.${clientId}.${tokens.username}.lastRefreshAttempt`;
    await storage.removeItem(attemptKey);
    logDebug(`Tab ${TAB_ID} cleared refresh attempt lock`);
  } catch (err) {
    // Non-critical error, just log it
    logDebug("Error clearing refresh attempt lock:", err);
  }
}

/**
 * Mark refresh as completed with retry logic
 */
async function markRefreshCompleted(): Promise<void> {
  const maxRetries = 3;
  let lastError: unknown;

  for (let attempt = 1; attempt <= maxRetries; attempt++) {
    try {
      const { storage, clientId } = configure();
      const tokens = await retrieveTokens();
      if (!tokens?.username) return;

      const completedKey = `Passwordless.${clientId}.${tokens.username}.lastRefreshCompleted`;
      await storage.setItem(completedKey, Date.now().toString());

      // Also clear the attempt lock since refresh is complete
      await clearRefreshAttemptLock();

      logDebug(`Tab ${TAB_ID} marked refresh as completed`);
      return; // Success
    } catch (err) {
      lastError = err;
      logDebug(
        `Error marking refresh completed (attempt ${attempt}/${maxRetries}):`,
        err
      );
      if (attempt < maxRetries) {
        // Wait before retry with exponential backoff
        await new Promise((resolve) => setTimeout(resolve, 100 * attempt));
      }
    }
  }

  // Log final failure but don't throw - this is supplementary
  logDebug("Failed to mark refresh completed after retries:", lastError);
}

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
async function handleVisibilityChange() {
  logDebug(
    `visibilitychange event: document.hidden=${globalThis.document.hidden}`
  );
  if (isDocumentVisible()) {
    // Get username to determine which state to check
    const tokens = await retrieveTokensForRefresh();
    const username = tokens?.username;
    const state = getRefreshState(username);
    
    // Skip if refresh is already in progress or scheduled
    if (state.isRefreshing || state.refreshTimer) {
      logDebug(
        "handleVisibilityChange: refresh already in progress or scheduled, skipping"
      );
      return;
    }

    // If page becomes visible and it's been a while since last refresh,
    // check if we need to schedule a refresh
    const timeThreshold = 60000; // 1 minute
    const lastRefresh = state.lastRefreshTime || 0;
    logDebug(
      `handleVisibilityChange: lastRefreshTime=${new Date(lastRefresh).toISOString()}`
    );

    if (Date.now() - lastRefresh > timeThreshold) {
      // Clear any existing visibility timer
      if (state.visibilityTimer) {
        clearTimeout(state.visibilityTimer);
        state.visibilityTimer = undefined;
      }

      // Small random delay to prevent thundering herd
      const randomDelay = Math.random() * 1000; // 0-1 second
      logDebug(
        `handleVisibilityChange: threshold passed, scheduling refresh with ${Math.round(randomDelay)}ms delay`
      );

      state.visibilityTimer = setTimeout(() => {
        state.visibilityTimer = undefined;

        // Handle async operations
        void (async () => {
          // Check if we should attempt
          if (!(await shouldAttemptRefresh())) {
            return;
          }

          // Re-check conditions after delay
          const currentState = getRefreshState(username);
          if (!currentState.isRefreshing && !currentState.refreshTimer) {
            logDebug("handleVisibilityChange: executing delayed refresh");
            void scheduleRefresh();
          }
        })();
      }, randomDelay);
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
  // Get current tokens first to determine username
  // Use retrieveTokensForRefresh to include expired tokens
  const tokens = await retrieveTokensForRefresh();
  if (abort?.aborted) return;

  if (!tokens?.expireAt || !tokens?.refreshToken) {
    logDebug("No valid tokens found, skipping refresh scheduling");
    // Don't clear tokens here - let other mechanisms handle expired/missing tokens
    return;
  }
  
  const username = tokens.username;
  const state = getRefreshState(username);
  
  // Skip if already scheduling
  if (state.isRefreshing) {
    logDebug("Token refresh already in progress, skipping");
    return;
  }

  // Skip if we already have a timer scheduled for the future
  if (state.refreshTimer && state.nextRefreshTime) {
    const timeUntilScheduledRefresh = state.nextRefreshTime - Date.now();
    if (timeUntilScheduledRefresh > 0) {
      logDebug(
        `Refresh already scheduled in ${Math.round(timeUntilScheduledRefresh / 60000)} minutes, skipping`
      );
      return;
    }
  }

  try {
    // Clear any existing timer
    const clearExistingTimer = () => {
      if (state.refreshTimer) {
        state.refreshTimer();
        state.refreshTimer = undefined;
        state.nextRefreshTime = undefined;
      }
    };
    clearExistingTimer();

    const tokenExpiryTime = tokens.expireAt.valueOf();
    const currentTime = Date.now();
    const timeUntilExpiry = tokenExpiryTime - currentTime;

    // If token is already expired or expires very soon, refresh immediately
    if (timeUntilExpiry <= 60000) {
      logDebug(
        `Token expires in ${Math.round(timeUntilExpiry / 1000)}s, refreshing immediately`
      );

      try {
        await refreshTokens({
          abort,
          tokensCb,
          isRefreshingCb,
          tokens,
          force: true,
        });

        // Mark as completed
        await markRefreshCompleted();

        // processTokens already handles scheduling the next refresh,
        // so we don't need to do it here
      } catch (err) {
        logDebug("Failed to refresh token:", err);
      }
      return;
    }

    // Standard case: schedule refresh with dynamic buffer
    let refreshDelay: number;

    try {
      if (tokens.accessToken) {
        const payload = parseJwtPayload<CognitoAccessTokenPayload>(
          tokens.accessToken
        );
        if (payload.iat && payload.exp) {
          const actualLifetime = (payload.exp - payload.iat) * 1000;
          const bufferTime = Math.max(
            60000,
            Math.min(0.3 * actualLifetime, 15 * 60 * 1000)
          );
          refreshDelay = Math.max(0, timeUntilExpiry - bufferTime);
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
      refreshDelay = Math.max(0, timeUntilExpiry / 2);
      logDebug(
        `Using fallback refresh timing (half remaining lifetime): delay=${Math.round(refreshDelay / 60000)}min`,
        err
      );
    }

    const desiredFireTime = Date.now() + refreshDelay;
    state.nextRefreshTime = desiredFireTime;

    const minutesUntilRefresh = Math.round(refreshDelay / (60 * 1000));
    logDebug(`Scheduling token refresh in ${minutesUntilRefresh} minutes`);

    state.refreshTimer = setTimeoutWallClock(async () => {
      state.refreshTimer = undefined;
      state.nextRefreshTime = undefined;
      try {
        const latestTokens = await retrieveTokensForRefresh();

        await refreshTokens({
          abort,
          tokensCb,
          isRefreshingCb,
          tokens: latestTokens,
        });
      } catch (err) {
        logDebug("Error during scheduled refresh:", err);
        consecutiveRefreshFailures++;

        if (consecutiveRefreshFailures >= MAX_CONSECUTIVE_REFRESH_FAILURES) {
          logDebug(
            `Max refresh failures (${MAX_CONSECUTIVE_REFRESH_FAILURES}) reached, giving up`
          );
          consecutiveRefreshFailures = 0; // Reset for next time
          return;
        }

        // Exponential backoff: 30s, 60s, 120s, 240s
        const backoffMs = Math.min(
          30000 * Math.pow(2, consecutiveRefreshFailures - 1),
          240000
        );
        logDebug(
          `Scheduling retry ${consecutiveRefreshFailures}/${MAX_CONSECUTIVE_REFRESH_FAILURES} in ${backoffMs / 1000}s`
        );

        setTimeoutWallClock(() => {
          void scheduleRefreshUnlocked({ abort, tokensCb, isRefreshingCb });
        }, backoffMs);
      }
    }, refreshDelay);

    abort?.addEventListener(
      "abort",
      () => {
        if (state.refreshTimer) {
          state.refreshTimer();
          state.refreshTimer = undefined;
          logDebug("Refresh scheduling aborted");
        }
      },
      { once: true }
    );
  } catch (err) {
    logDebug("Error scheduling refresh:", err);
  }
}

// Simplified wrapper with per-user lock
export async function scheduleRefresh(
  args: Parameters<typeof scheduleRefreshUnlocked>[0] = {}
): Promise<void> {
  const { clientId, debug } = configure();
  const tokens0 = await retrieveTokens();
  const userIdentifier = tokens0?.username;
  if (!userIdentifier) {
    debug?.("scheduleRefresh: no user, running unlocked");
    return scheduleRefreshUnlocked(args);
  }

  const lockKey = `Passwordless.${clientId}.${userIdentifier}.refreshLock`;
  debug?.("scheduleRefresh: waiting for lock", lockKey);

  try {
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
  } catch (err) {
    if (err instanceof LockTimeoutError) {
      debug?.(
        "scheduleRefresh: could not acquire lock, another tab is handling refresh"
      );
      // This is fine - another tab is already refreshing
      return;
    }
    // Re-throw other errors
    throw err;
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

  const tokenEndpoint = getTokenEndpoint();
  debug?.(`Using OAuth token endpoint: ${tokenEndpoint}`);

  const body = new URLSearchParams({
    grant_type: "refresh_token",
    client_id: clientId,
    refresh_token: refreshToken,
  });

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
  const { clientId } = configure();
  let userIdentifier: string | undefined = tokens?.username;
  if (!userIdentifier) {
    const storedTokens = await retrieveTokens();
    userIdentifier = storedTokens?.username;
  }
  if (!userIdentifier) {
    throw new Error("Cannot determine user identity for refresh lock");
  }
  const lockKey = `Passwordless.${clientId}.${userIdentifier}.refreshLock`;

  const doRefresh = async (): Promise<TokensFromRefresh> => {
    // Get state for this user
    const state = getRefreshState(userIdentifier);
    
    if (state.isRefreshing && !force) {
      logDebug("Token refresh already in progress");
      throw new Error("Token refresh already in progress");
    }

    // Check if another tab is about to refresh or just did
    if (!force && !(await shouldAttemptRefresh())) {
      logDebug("Another tab is handling refresh, skipping");
      throw new Error("Another tab is handling refresh");
    }

    try {
      state.isRefreshing = true;
      isRefreshingCb?.(true);

      if (!tokens) {
        tokens = await retrieveTokens();
      }

      const refreshToken = tokens?.refreshToken;
      const username = tokens?.username;
      const deviceKey = tokens?.deviceKey;
      const expireAt = tokens?.expireAt;
      const authMethod = tokens?.authMethod;

      if (!refreshToken || !username) {
        throw new Error("Cannot refresh without refresh token and username");
      }

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

      let tokensFromRefresh: TokensFromRefresh;

      try {
        const { debug, useGetTokensFromRefreshToken } = configure();
        let authResult;
        if (authMethod === "REDIRECT") {
          debug?.(
            "Using OAuth token endpoint for refresh since auth method is REDIRECT"
          );
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
            let lastError: Error | undefined;
            let currentRefreshToken = refreshToken;
            const maxRetries = 3;

            for (let attempt = 1; attempt <= maxRetries; attempt++) {
              try {
                authResult = await getTokensFromRefreshToken({
                  refreshToken: currentRefreshToken,
                  deviceKey,
                  abort,
                });
                break;
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
                    currentRefreshToken = latestToken;
                    continue;
                  } else {
                    throw err;
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
                  await new Promise((resolve) =>
                    setTimeout(resolve, 1000 * attempt)
                  );
                  continue;
                } else {
                  throw err;
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

        let expireAt: Date;
        try {
          const { exp } = parseJwtPayload<CognitoAccessTokenPayload>(
            authResult.AuthenticationResult.AccessToken
          );
          expireAt = new Date(exp * 1000);
        } catch {
          expireAt = new Date(
            Date.now() + authResult.AuthenticationResult.ExpiresIn * 1000
          );
        }

        tokensFromRefresh = {
          accessToken: authResult.AuthenticationResult.AccessToken,
          ...(authResult.AuthenticationResult.IdToken && {
            idToken: authResult.AuthenticationResult.IdToken,
          }),
          expireAt,
          username,
          refreshToken:
            authResult.AuthenticationResult.RefreshToken ?? refreshToken,
          ...(deviceKey && { deviceKey }),
          ...(authMethod && { authMethod }),
        };

        logDebug(
          `Token refreshed; new refresh token received: ${authResult.AuthenticationResult.RefreshToken ? "yes" : "no"}, expires in ${authResult.AuthenticationResult.ExpiresIn}s`
        );
      } catch (error) {
        logDebug("Token refresh failed:", error);
        state.lastRefreshTime = Date.now();
        // Clear the attempt lock on error so other tabs can retry
        await clearRefreshAttemptLock();
        throw error;
      }

      let processedTokens: TokensFromRefresh;
      try {
        processedTokens = (await processTokens(
          tokensFromRefresh,
          abort
        )) as TokensFromRefresh;
        state.lastRefreshTime = Date.now();

        // Call tokensCb first - if it fails, we don't want to mark as completed
        if (tokensCb) {
          await tokensCb(processedTokens);
        }

        // Only mark as completed after everything succeeds
        await markRefreshCompleted();

        // Reset failure counter on success
        consecutiveRefreshFailures = 0;
      } catch (error) {
        // If anything fails after we got new tokens, we need to clear the attempt lock
        // so other tabs can retry
        logDebug("Error during token processing or callback:", error);
        await clearRefreshAttemptLock();
        throw error;
      }

      return processedTokens;
    } finally {
      state.isRefreshing = false;
      isRefreshingCb?.(false);
    }
  };

  const { debug } = configure();
  if (force) {
    debug?.("refreshTokens: force=true, bypassing lock", lockKey);
    return doRefresh();
  }
  debug?.("refreshTokens: waiting for lock", lockKey);
  try {
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
  } catch (err) {
    if (
      err instanceof LockTimeoutError ||
      (err instanceof Error &&
        err.message === "Another tab is handling refresh")
    ) {
      debug?.(
        err instanceof LockTimeoutError
          ? "refreshTokens: could not acquire lock, another process is refreshing"
          : "refreshTokens: another tab is handling refresh (coordination check)"
      );

      // Wait for the other tab's refresh to complete
      // Increased to handle slow network conditions
      const waitTime = 2000; // 2 seconds
      debug?.(
        `refreshTokens: waiting ${waitTime}ms for other tab's refresh to complete`
      );

      // Store the current token state before waiting
      const tokensBeforeWait = await retrieveTokens();
      const accessTokenBeforeWait = tokensBeforeWait?.accessToken;

      await new Promise((resolve) => setTimeout(resolve, waitTime));

      // Check if tokens were actually refreshed by comparing the access token
      const currentTokens = await retrieveTokens();

      // If the access token changed, it means a refresh occurred
      if (
        currentTokens?.accessToken &&
        currentTokens.accessToken !== accessTokenBeforeWait
      ) {
        debug?.(
          "refreshTokens: tokens were refreshed by another tab (access token changed)"
        );
        if (
          currentTokens.expireAt &&
          currentTokens.refreshToken &&
          currentTokens.username
        ) {
          const refreshedTokens: TokensFromRefresh = {
            accessToken: currentTokens.accessToken,
            ...(currentTokens.idToken && { idToken: currentTokens.idToken }),
            expireAt: currentTokens.expireAt,
            username: currentTokens.username,
            refreshToken: currentTokens.refreshToken,
            ...(currentTokens.deviceKey && {
              deviceKey: currentTokens.deviceKey,
            }),
            ...(currentTokens.authMethod && {
              authMethod: currentTokens.authMethod,
            }),
          };

          if (tokensCb) {
            await tokensCb(refreshedTokens);
          }

          return refreshedTokens;
        } else {
          debug?.(
            "refreshTokens: tokens were refreshed but missing required fields",
            {
              hasExpireAt: !!currentTokens.expireAt,
              hasRefreshToken: !!currentTokens.refreshToken,
              hasUsername: !!currentTokens.username,
            }
          );
          throw new Error(
            "Tokens were refreshed by another tab but are incomplete"
          );
        }
      } else {
        debug?.(
          "refreshTokens: tokens were NOT refreshed by another tab (access token unchanged)"
        );
        throw new Error(
          "Another refresh in progress and no valid tokens available"
        );
      }
    }
    throw err;
  }
}

/**
 * Force an immediate token refresh
 */
export async function forceRefreshTokens(
  args?: Omit<Parameters<typeof refreshTokens>[0], "force">
): Promise<TokensFromRefresh> {
  logDebug("Forcing immediate token refresh");

  // Get username to clear the right timer
  const tokens = await retrieveTokens();
  const username = tokens?.username;
  const state = getRefreshState(username);
  
  if (state.refreshTimer) {
    state.refreshTimer();
    state.refreshTimer = undefined;
  }

  const refreshed = await refreshTokens({
    ...(args ?? {}),
    force: true,
  });

  void scheduleRefresh({ ...args });

  return refreshed;
}

// Initialize visibility change listener for browser environments
if (isBrowserEnvironment()) {
  // Create named handler for proper cleanup
  const visibilityHandler = () => {
    void handleVisibilityChange();
  };
  
  // eslint-disable-next-line no-restricted-globals
  globalThis.document.addEventListener(
    "visibilitychange",
    visibilityHandler
  );
  
  // Store cleanup function  
  visibilityChangeListener = () => {
    globalThis.document.removeEventListener(
      "visibilitychange",
      visibilityHandler
    );
  };

  // Simplified watchdog with cleanup support
  const WATCHDOG_INTERVAL_MS = 5 * 60 * 1000;
  const startWatchdog = () => {
    const cleanup = setTimeoutWallClock(() => {
      void (async () => {
      logDebug(`Watchdog tick at ${new Date().toISOString()}`);
      
      // Check all users' refresh states
      const tokens = await retrieveTokensForRefresh();
      const username = tokens?.username;
      const state = getRefreshState(username);
      
      if (!state.refreshTimer && isDocumentVisible()) {
        const lastRefresh = state.lastRefreshTime || 0;
        if (Date.now() - lastRefresh > WATCHDOG_INTERVAL_MS) {
          logDebug("Watchdog is triggering a refresh check");
          void (async () => {
            if (await shouldAttemptRefresh()) {
              void scheduleRefresh();
            }
          })();
        }
      }
      // Only continue if cleanup hasn't been called
      if (watchdogCleanup) {
        watchdogCleanup = startWatchdog();
      }
      })();
    }, WATCHDOG_INTERVAL_MS);
    return cleanup;
  };
  watchdogCleanup = startWatchdog();
}

/**
 * Clean up all refresh-related timers and event listeners.
 * Call this when unmounting the application or switching users.
 * @param username - Optional username to clean up specific user state
 */
export function cleanupRefreshSystem(username?: string): void {
  logDebug("Cleaning up refresh system");

  // Clean up visibility change listener
  if (visibilityChangeListener) {
    visibilityChangeListener();
    visibilityChangeListener = undefined;
  }

  // Clean up watchdog timer
  if (watchdogCleanup) {
    watchdogCleanup();
    watchdogCleanup = undefined;
  }

  // Get the appropriate refresh state
  const state = getRefreshState(username);

  // Clean up any active refresh timer
  if (state.refreshTimer) {
    state.refreshTimer();
    state.refreshTimer = undefined;
    state.nextRefreshTime = undefined;
  }

  // Clean up visibility timer
  if (state.visibilityTimer) {
    clearTimeout(state.visibilityTimer);
    state.visibilityTimer = undefined;
  }

  // Reset refresh state
  state.isRefreshing = false;
  state.lastRefreshTime = undefined;

  // Clear user-specific state from the map
  if (username) {
    clearRefreshState(username);
  }
}
