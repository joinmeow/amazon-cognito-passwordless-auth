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

const refreshState: RefreshState = {
  isRefreshing: false,
};

// Generate unique tab ID for this tab
const TAB_ID =
  typeof globalThis.crypto !== "undefined" && globalThis.crypto.randomUUID
    ? globalThis.crypto.randomUUID()
    : `${Date.now()}-${Math.random().toString(36).substring(2, 11)}`;

/**
 * Atomic refresh coordination using compare-and-swap pattern
 */
async function shouldAttemptRefresh(): Promise<boolean> {
  try {
    const { storage, clientId } = configure();
    const tokens = await retrieveTokens();
    if (!tokens?.username) return false;

    const attemptKey = `Passwordless.${clientId}.${tokens.username}.lastRefreshAttempt`;

    // Use a unique value that includes our tab ID and timestamp
    const now = Date.now();
    const ourValue = `${now}:${TAB_ID}`;

    // Attempt to claim the refresh slot atomically
    // This works by:
    // 1. Always writing our value (timestamp:tabId)
    // 2. Reading it back immediately
    // 3. If we read our value, we won the race
    // 4. If we read a different value, another tab won
    // This pattern eliminates the race window between check and set

    await storage.setItem(attemptKey, ourValue);
    const readBackValue = await storage.getItem(attemptKey);

    if (readBackValue !== ourValue) {
      // Another tab won the race, check if their attempt is recent
      const match = readBackValue?.match(/^(\d+):/);
      if (match) {
        const otherTabTime = parseInt(match[1], 10);
        const timeSinceOtherAttempt = now - otherTabTime;

        if (timeSinceOtherAttempt < 30000) {
          logDebug(
            `Another tab claimed refresh ${timeSinceOtherAttempt}ms ago, skipping`
          );
          return false;
        }

        // Other attempt is stale, try to claim again
        await storage.setItem(attemptKey, ourValue);
        const secondRead = await storage.getItem(attemptKey);
        if (secondRead !== ourValue) {
          logDebug("Lost race condition on second attempt, skipping");
          return false;
        }
      }
    }

    logDebug(`Tab ${TAB_ID} successfully claimed refresh attempt`);
    return true;
  } catch (err) {
    // If storage fails, allow attempt (fail open)
    logDebug("Error checking refresh coordination:", err);
    return true;
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
function handleVisibilityChange() {
  logDebug(
    `visibilitychange event: document.hidden=${globalThis.document.hidden}`
  );
  if (isDocumentVisible()) {
    // Skip if refresh is already in progress or scheduled
    if (refreshState.isRefreshing || refreshState.refreshTimer) {
      logDebug(
        "handleVisibilityChange: refresh already in progress or scheduled, skipping"
      );
      return;
    }

    // If page becomes visible and it's been a while since last refresh,
    // check if we need to schedule a refresh
    const timeThreshold = 60000; // 1 minute
    const lastRefresh = refreshState.lastRefreshTime || 0;
    logDebug(
      `handleVisibilityChange: lastRefreshTime=${new Date(lastRefresh).toISOString()}`
    );

    if (Date.now() - lastRefresh > timeThreshold) {
      // Clear any existing visibility timer
      if (refreshState.visibilityTimer) {
        clearTimeout(refreshState.visibilityTimer);
        refreshState.visibilityTimer = undefined;
      }

      // Small random delay to prevent thundering herd
      const randomDelay = Math.random() * 1000; // 0-1 second
      logDebug(
        `handleVisibilityChange: threshold passed, scheduling refresh with ${Math.round(randomDelay)}ms delay`
      );

      refreshState.visibilityTimer = setTimeout(() => {
        refreshState.visibilityTimer = undefined;

        // Handle async operations
        void (async () => {
          // Check if we should attempt
          if (!(await shouldAttemptRefresh())) {
            return;
          }

          // Re-check conditions after delay
          if (!refreshState.isRefreshing && !refreshState.refreshTimer) {
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
  // Skip if already scheduling
  if (refreshState.isRefreshing) {
    logDebug("Token refresh already in progress, skipping");
    return;
  }

  // Skip if we already have a timer scheduled for the future
  if (refreshState.refreshTimer && refreshState.nextRefreshTime) {
    const timeUntilScheduledRefresh = refreshState.nextRefreshTime - Date.now();
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
      logDebug(
        `Token expires in ${Math.round(timeUntilExpiry / 1000)}s, refreshing now`
      );

      try {
        const refreshedTokens = await refreshTokens({
          abort,
          tokensCb,
          isRefreshingCb,
          tokens,
          force: true,
        });

        // Mark as completed
        await markRefreshCompleted();

        // After a successful immediate refresh, schedule the next refresh
        if (refreshedTokens?.expireAt) {
          const newTimeUntilExpiry =
            refreshedTokens.expireAt.valueOf() - Date.now();
          if (newTimeUntilExpiry > 60000) {
            logDebug("Immediate refresh complete, scheduling next refresh");
            return scheduleRefreshUnlocked({ abort, tokensCb, isRefreshingCb });
          }
        }
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
    refreshState.nextRefreshTime = desiredFireTime;

    const minutesUntilRefresh = Math.round(refreshDelay / (60 * 1000));
    logDebug(`Scheduling token refresh in ${minutesUntilRefresh} minutes`);

    refreshState.refreshTimer = setTimeoutWallClock(async () => {
      refreshState.refreshTimer = undefined;
      refreshState.nextRefreshTime = undefined;
      try {
        const latestTokens = await retrieveTokens();

        await refreshTokens({
          abort,
          tokensCb: async (refreshedTokens) => {
            await tokensCb?.(refreshedTokens);
            await markRefreshCompleted();
          },
          isRefreshingCb,
          tokens: latestTokens,
        });
      } catch (err) {
        logDebug("Error during scheduled refresh:", err);
        setTimeoutWallClock(() => {
          void scheduleRefreshUnlocked({ abort, tokensCb, isRefreshingCb });
        }, 30000); // 30 second backoff
      }
    }, refreshDelay);

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
    if (refreshState.isRefreshing && !force) {
      logDebug("Token refresh already in progress");
      throw new Error("Token refresh already in progress");
    }

    try {
      refreshState.isRefreshing = true;
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
        refreshState.lastRefreshTime = Date.now();
        throw error;
      }

      const processedTokens = await processTokens(tokensFromRefresh, abort);
      refreshState.lastRefreshTime = Date.now();

      if (tokensCb) {
        await tokensCb(processedTokens as TokensFromRefresh);
      }

      return processedTokens as TokensFromRefresh;
    } finally {
      refreshState.isRefreshing = false;
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
    if (err instanceof LockTimeoutError) {
      debug?.(
        "refreshTokens: could not acquire lock, another process is refreshing"
      );
      const currentTokens = await retrieveTokens();
      if (
        currentTokens?.accessToken &&
        currentTokens?.idToken &&
        currentTokens?.expireAt &&
        currentTokens?.refreshToken
      ) {
        return {
          accessToken: currentTokens.accessToken,
          idToken: currentTokens.idToken,
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
      }
      throw new Error(
        "Another refresh in progress and no valid tokens available"
      );
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

  if (refreshState.refreshTimer) {
    refreshState.refreshTimer();
    refreshState.refreshTimer = undefined;
  }

  const refreshed = await refreshTokens({
    ...(args ?? {}),
    force: true,
  });

  await markRefreshCompleted();
  void scheduleRefresh({ ...args });

  return refreshed;
}

// Initialize visibility change listener for browser environments
if (isBrowserEnvironment()) {
  // eslint-disable-next-line no-restricted-globals
  globalThis.document.addEventListener(
    "visibilitychange",
    handleVisibilityChange
  );

  // Simplified watchdog
  const WATCHDOG_INTERVAL_MS = 5 * 60 * 1000;
  const startWatchdog = () => {
    setTimeoutWallClock(() => {
      logDebug(`Watchdog tick at ${new Date().toISOString()}`);
      if (!refreshState.refreshTimer && isDocumentVisible()) {
        const lastRefresh = refreshState.lastRefreshTime || 0;
        if (Date.now() - lastRefresh > WATCHDOG_INTERVAL_MS) {
          logDebug("Watchdog is triggering a refresh check");
          void (async () => {
            if (await shouldAttemptRefresh()) {
              void scheduleRefresh();
            }
          })();
        }
      }
      startWatchdog();
    }, WATCHDOG_INTERVAL_MS);
  };
  startWatchdog();
}
