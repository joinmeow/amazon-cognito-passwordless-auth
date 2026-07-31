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
import { withLock, isLockTimeoutError } from "./lock.js";

// Simple state tracking
type RefreshState = {
  isRefreshing: boolean;
  refreshTimer?: ReturnType<typeof setTimeoutWallClock>;
  /** Wall-clock timestamp (ms) when the current refreshTimer is scheduled to fire */
  nextRefreshTime?: number;
  lastRefreshTime?: number;
  /** Wall-clock timestamp (ms) when refresh was last scheduled */
  lastScheduleTime?: number;
  /**
   * Per-user count of consecutive scheduled-refresh failures, driving the
   * failure backoff. Per-user (not module-global) so one user's repeated
   * failures don't throttle another user's backoff after a user switch.
   * Reset to 0 on a successful refresh, on hitting the failure cap, and on
   * user teardown (cleanupUserRefreshState).
   */
  consecutiveFailures: number;
  /**
   * Cancel handle for the failure-backoff retry timer armed after a failed
   * scheduled refresh. Tracked per-user so cleanupUserRefreshState, the
   * schedule abort, and forceRefreshTokens can cancel it — otherwise it can
   * fire for a session that has already been signed out / torn down.
   */
  retryTimer?: ReturnType<typeof setTimeoutWallClock>;
};

// Per-user refresh state to prevent conflicts
const refreshStateMap = new Map<string, RefreshState>();

// Get or create refresh state for a user
function getRefreshState(username?: string): RefreshState {
  if (!username) {
    // For operations without a username (like initial page load),
    // create a temporary state that won't interfere with user-specific states
    return { isRefreshing: false, consecutiveFailures: 0 };
  }

  let state = refreshStateMap.get(username);
  if (!state) {
    state = { isRefreshing: false, consecutiveFailures: 0 };
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
let autoCleanupHandler: (() => void) | undefined;

// Max consecutive refresh failures before giving up
const MAX_CONSECUTIVE_REFRESH_FAILURES = 5;

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
    // Use retrieveTokensForRefresh: the access token may already be expired,
    // which is precisely when a refresh attempt matters most
    const tokens = await retrieveTokensForRefresh();
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
    // Use retrieveTokensForRefresh: this runs on failure paths where the
    // access token may be expired, but the lock must still be cleared
    const tokens = await retrieveTokensForRefresh();
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
      const tokens = await retrieveTokensForRefresh();
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
  if (!isDocumentVisible()) return;

  const tokens = await retrieveTokensForRefresh();
  if (!tokens?.expireAt) return;

  const state = getRefreshState(tokens.username);

  // If already refreshing or has a timer, trust it
  if (state.isRefreshing || state.refreshTimer) {
    logDebug(
      "handleVisibilityChange: refresh already in progress or scheduled, skipping"
    );
    return;
  }

  const timeUntilExpiry = tokens.expireAt.getTime() - Date.now();

  // Only intervene if tokens are about to expire and nothing is scheduled
  if (timeUntilExpiry < 5 * 60 * 1000) {
    logDebug(
      `handleVisibilityChange: tokens expiring in ${Math.round(timeUntilExpiry / 1000)}s, scheduling refresh`
    );
    void scheduleRefresh();
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
 * Arm (or immediately run) this user's token refresh. Timer calculation and
 * registration run WITHOUT the refresh lock: arming a timer is purely local,
 * in-memory work, and holding `.refreshLock` here is what let an orphaned lock
 * from a dead tab stall scheduling. The immediate-refresh branch delegates to
 * refreshTokens(), which takes the lock itself and serializes across tabs. A
 * sign-out cancels an armed timer through the schedule's abort signal, and a
 * timer that fires for a torn-down session is discarded by refreshTokens'
 * re-validation.
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
      // A fresh schedule supersedes any pending failure-backoff retry: cancel
      // it too, otherwise a stale retry from a prior failure fires an extra
      // refresh after we re-arm. (The other re-entry points — abort,
      // cleanupUserRefreshState, forceRefreshTokens — already cancel it.)
      if (state.retryTimer) {
        state.retryTimer();
        state.retryTimer = undefined;
      }
    };
    clearExistingTimer();

    const tokenExpiryTime = tokens.expireAt.valueOf();
    // Evaluate against a skew-corrected clock (local time minus the drift
    // captured at receipt) so a wrong device clock doesn't make us treat valid
    // tokens as already-expired and refresh in a tight loop.
    const currentTime = Date.now() - (tokens.clockDriftMs ?? 0);
    const timeUntilExpiry = tokenExpiryTime - currentTime;

    // If token is already expired or expires very soon, refresh immediately
    if (timeUntilExpiry <= 60000) {
      logDebug(
        `Token expires in ${Math.round(timeUntilExpiry / 1000)}s, refreshing immediately`
      );

      try {
        // Route the immediate refresh through refreshTokens so it takes the
        // per-user lock itself — scheduling no longer holds it. refreshTokens
        // marks completion, and its processTokens schedules the next refresh.
        await refreshTokens({
          abort,
          tokensCb,
          isRefreshingCb,
          tokens,
          force: true,
        });
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
    state.lastScheduleTime = Date.now();

    const minutesUntilRefresh = Math.round(refreshDelay / (60 * 1000));
    logDebug(`Scheduling token refresh in ${minutesUntilRefresh} minutes`);

    state.refreshTimer = setTimeoutWallClock(async () => {
      state.refreshTimer = undefined;
      state.nextRefreshTime = undefined;
      try {
        const latestTokens = await retrieveTokensForRefresh();

        // An already-expired access token (e.g. the timer fired on wake from
        // sleep, long past its due time) has no cached-token fallback: the
        // refresh must actually happen. Force so it queues for the lock like
        // the immediate-refresh branch does, instead of the best-effort
        // try-lock-and-skip a due-at-half-life refresh gets.
        const alreadyExpired =
          !!latestTokens?.expireAt &&
          latestTokens.expireAt.valueOf() <=
            Date.now() - (latestTokens.clockDriftMs ?? 0);

        await refreshTokens({
          abort,
          tokensCb,
          isRefreshingCb,
          tokens: latestTokens,
          force: alreadyExpired,
        });

        // refreshTokens can succeed WITHOUT this tab having refreshed —
        // adopting another tab's result, or returning the still-valid cached
        // token when the lock was contended. Those paths never reach
        // processTokens, so no next timer is armed and the chain would stall
        // until the watchdog. Re-arm here: when this tab DID refresh,
        // processTokens already registered the next timer and scheduleRefresh
        // dedups against it, so this is a no-op on that path.
        void scheduleRefresh({ abort, tokensCb, isRefreshingCb });
      } catch (err) {
        logDebug("Error during scheduled refresh:", err);

        // The scheduled refresh ran and failed, but the session may have been
        // torn down WHILE refreshTokens() was in flight: the abort could have
        // fired, or cleanupUserRefreshState()/signOut() could have deleted this
        // user's state from refreshStateMap, orphaning the `state` captured in
        // this closure. The abort listener and cleanup only cancel a retry that
        // is already armed; a teardown landing before this catch leaves nothing
        // to cancel. Arming a retry on a torn-down state would resurrect refresh
        // scheduling for whatever session is in storage, so bail out without
        // touching the stale state. Also bail when there is no username: a
        // no-username refresh runs on a throwaway state never stored in
        // refreshStateMap, so a retry armed on it could never be cancelled.
        if (
          abort?.aborted ||
          !username ||
          refreshStateMap.get(username) !== state
        ) {
          logDebug(
            "Session torn down (or no user) during the failed refresh; not scheduling a retry"
          );
          return;
        }

        state.consecutiveFailures++;

        if (state.consecutiveFailures >= MAX_CONSECUTIVE_REFRESH_FAILURES) {
          logDebug(
            `Max refresh failures (${MAX_CONSECUTIVE_REFRESH_FAILURES}) reached, giving up`
          );
          state.consecutiveFailures = 0; // Reset for next time
          return;
        }

        // Exponential backoff: 30s, 60s, 120s, 240s
        const backoffMs = Math.min(
          30000 * Math.pow(2, state.consecutiveFailures - 1),
          240000
        );
        logDebug(
          `Scheduling retry ${state.consecutiveFailures}/${MAX_CONSECUTIVE_REFRESH_FAILURES} in ${backoffMs / 1000}s`
        );

        // Track the retry timer in the per-user state so it can be cancelled
        // (cleanupUserRefreshState, the schedule abort, forceRefreshTokens):
        // otherwise it fires for a session that may already be torn down.
        state.retryTimer = setTimeoutWallClock(() => {
          state.retryTimer = undefined;
          void scheduleRefresh({ abort, tokensCb, isRefreshingCb });
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
        // Also cancel any pending failure-backoff retry timer so an aborted
        // schedule can't resurrect itself after sign-out/teardown.
        if (state.retryTimer) {
          state.retryTimer();
          state.retryTimer = undefined;
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

/** Public options for {@link refreshTokens}. */
export interface RefreshTokensOptions {
  abort?: AbortSignal;
  tokensCb?: (res: TokensFromRefresh) => void | Promise<void>;
  isRefreshingCb?: (isRefreshing: boolean) => unknown;
  tokens?: TokenPayload;
  /**
   * Skip the cross-tab `shouldAttemptRefresh()` coordination/dedup check and
   * the in-process `isRefreshing` guard: the caller wants a refresh NOW
   * (e.g. after a 401), regardless of the 5s dedup window. Does NOT bypass
   * the per-user refresh lock, so it still serializes with other refreshes.
   */
  force?: boolean;
}

/**
 * Refresh this user's tokens under the per-user refresh lock, which serializes
 * refreshes across tabs. A sign-out that raced the network round-trip is
 * detected afterwards (session re-validation here plus the sign-out tombstone
 * re-checked in processTokens) and the refreshed tokens are discarded rather
 * than resurrecting the signed-out session.
 */
export async function refreshTokens({
  abort,
  tokensCb,
  isRefreshingCb,
  tokens,
  force = false,
}: RefreshTokensOptions = {}): Promise<TokensFromRefresh> {
  const { clientId } = configure();
  let userIdentifier: string | undefined = tokens?.username;
  if (!userIdentifier) {
    // Use retrieveTokensForRefresh: the access token may already be expired
    // (e.g. device woke from sleep), but the refresh token can still be valid
    const storedTokens = await retrieveTokensForRefresh();
    userIdentifier = storedTokens?.username;
  }
  if (!userIdentifier) {
    throw new Error("Cannot determine user identity for refresh lock");
  }
  const lockKey = `Passwordless.${clientId}.${userIdentifier}.refreshLock`;

  const doRefresh = async (): Promise<TokensFromRefresh> => {
    // A sign-out tombstone newer than this moment means the user signed
    // out while this refresh was in flight; the result must be discarded
    const refreshStart = Date.now();
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
        // Use retrieveTokensForRefresh to include expired tokens
        tokens = await retrieveTokensForRefresh();
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
                  const latestStored = await retrieveTokensForRefresh();
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

      // Sign-out does not take the refresh lock, so it can have landed during
      // this round-trip. Re-validate the session before writing anything back:
      // storing now would resurrect the session the user just signed out of.
      // (A rotated refresh token dies with this discard — RevokeToken revokes
      // the whole token family, so it is unusable.)
      const sessionStillExists = await retrieveTokensForRefresh();
      if (
        !sessionStillExists?.refreshToken ||
        sessionStillExists.username !== username
      ) {
        logDebug(
          "Session was signed out during the refresh round-trip; discarding refreshed tokens"
        );
        await clearRefreshAttemptLock();
        throw new Error(
          "Session was signed out during the token refresh; refreshed tokens discarded"
        );
      }

      // Cleared before processTokens, which fire-and-forget schedules the next
      // refresh and skips scheduling while this flag is set — otherwise
      // short-lived tokens never get their next timer armed. Mutual exclusion
      // is held by the refresh lock, not this flag.
      state.isRefreshing = false;

      let processedTokens: TokensFromRefresh;
      try {
        processedTokens = (await processTokens(tokensFromRefresh, abort, {
          // The authoritative race guard: processTokens re-validates the
          // session (and the sign-out tombstone) immediately before AND
          // after the write, under the auth lock
          sessionMustExistSince: refreshStart,
        })) as TokensFromRefresh;
        state.lastRefreshTime = Date.now();

        // Call tokensCb first - if it fails, we don't want to mark as completed
        if (tokensCb) {
          await tokensCb(processedTokens);
        }

        // Only mark as completed after everything succeeds
        await markRefreshCompleted();

        // Reset this user's failure counter on success
        state.consecutiveFailures = 0;
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
  debug?.("refreshTokens: waiting for lock", lockKey);
  try {
    const result = await withLock(
      lockKey,
      async () => {
        debug?.("refreshTokens: lock acquired", lockKey);
        return doRefresh();
      },
      // A non-forced (background/scheduled) refresh is best-effort: if the
      // lock is held, whoever holds it IS refreshing this user's tokens, so
      // skip straight to the recovery below (adopt their result, or return
      // the still-valid cached token) instead of queueing behind them.
      // A forced refresh (e.g. after a 401) needs a fresh token and must
      // wait its turn.
      force ? undefined : 0,
      abort
    );
    debug?.("refreshTokens: lock released", lockKey);
    return result;
  } catch (err) {
    if (
      isLockTimeoutError(err) ||
      (err instanceof Error &&
        err.message === "Another tab is handling refresh")
    ) {
      debug?.(
        isLockTimeoutError(err)
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
            // Carry over the clock drift persisted by the tab that refreshed,
            // so the skew-corrected expiry check stays correct in this tab too.
            ...(currentTokens.clockDriftMs !== undefined && {
              clockDriftMs: currentTokens.clockDriftMs,
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
        // The holder didn't finish within the wait. For a background refresh,
        // a still-valid cached token beats an error: retrieveTokens() already
        // returned undefined if the access token were expired (skew-corrected),
        // so a non-null result here IS valid. Surfacing an error instead would
        // let a spurious lock timeout (e.g. a timer that fired while the event
        // loop was parked through laptop sleep) look like an auth failure.
        // tokensCb is deliberately NOT called: these are the tokens the caller
        // already has, not a state change to propagate.
        if (
          !force &&
          currentTokens?.accessToken &&
          currentTokens.expireAt &&
          currentTokens.refreshToken &&
          currentTokens.username
        ) {
          debug?.(
            "refreshTokens: lock unavailable but cached access token is still valid; returning it"
          );
          return {
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
            ...(currentTokens.clockDriftMs !== undefined && {
              clockDriftMs: currentTokens.clockDriftMs,
            }),
          };
        }
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
  args?: Omit<RefreshTokensOptions, "force">
): Promise<TokensFromRefresh> {
  logDebug("Forcing immediate token refresh");

  // Get username to clear the right timer (include expired tokens, since
  // forcing a refresh is most relevant when the access token already expired)
  const tokens = await retrieveTokensForRefresh();
  const username = tokens?.username;
  const state = getRefreshState(username);

  if (state.refreshTimer) {
    state.refreshTimer();
    state.refreshTimer = undefined;
  }
  // Cancel any pending failure-backoff retry timer too: we are about to
  // refresh now, so a stale backoff retry must not fire afterwards.
  if (state.retryTimer) {
    state.retryTimer();
    state.retryTimer = undefined;
  }

  // force: true skips the dedup/coordination check, but refreshTokens still
  // takes the per-user lock and re-validates against sign-out afterwards, so a
  // forced refresh racing a concurrent sign-out cannot resurrect the session it
  // just removed.
  const refreshed = await refreshTokens({
    ...(args ?? {}),
    force: true,
  });

  // scheduleRefresh's tokensCb is nullable (scheduling can yield null tokens)
  // while the forced-refresh tokensCb is not; the spread is behaviourally the
  // same as before, the cast just bridges that variance difference
  void scheduleRefresh({ ...args } as Parameters<typeof scheduleRefresh>[0]);

  return refreshed;
}

// Initialize visibility change listener for browser environments
if (isBrowserEnvironment()) {
  // Create named handler for proper cleanup
  const visibilityHandler = () => {
    void handleVisibilityChange();
  };

  // eslint-disable-next-line no-restricted-globals
  globalThis.document.addEventListener("visibilitychange", visibilityHandler);

  // Store cleanup function
  visibilityChangeListener = () => {
    globalThis.document.removeEventListener(
      "visibilitychange",
      visibilityHandler
    );
  };

  // AUTO-CLEANUP: Clean up on page unload/hide
  autoCleanupHandler = () => {
    logDebug("Auto-cleanup triggered on page unload/hide");
    cleanupRefreshSystem();
  };

  // Deliberately NO "unload" listener: its mere presence makes the page
  // ineligible for the back/forward cache in desktop Chrome and Firefox, and
  // pagehide fires in every case unload does (plus when the page enters
  // bfcache), so it adds nothing. See https://web.dev/articles/bfcache
  globalThis.addEventListener("beforeunload", autoCleanupHandler);
  globalThis.addEventListener("pagehide", autoCleanupHandler);

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
 * Clean up refresh state for a specific user (timers and in-memory state).
 * Call this on sign-out: it does NOT remove the global visibilitychange,
 * watchdog and page-lifecycle listeners, so token refresh keeps working
 * when another user signs in afterwards.
 * @param username - Optional username to clean up specific user state
 */
export function cleanupUserRefreshState(username?: string): void {
  logDebug("Cleaning up user refresh state");

  // Get the appropriate refresh state
  const state = getRefreshState(username);

  // Clean up any active refresh timer
  if (state.refreshTimer) {
    state.refreshTimer();
    state.refreshTimer = undefined;
    state.nextRefreshTime = undefined;
  }

  // Cancel any pending failure-backoff retry timer so it can't fire (and
  // re-schedule a refresh) for a session that has just been signed out.
  if (state.retryTimer) {
    state.retryTimer();
    state.retryTimer = undefined;
  }

  // Reset refresh state
  state.isRefreshing = false;
  state.lastRefreshTime = undefined;
  state.consecutiveFailures = 0;

  // Clear user-specific state from the map
  if (username) {
    clearRefreshState(username);
  }
}

/**
 * Clean up all refresh-related timers and event listeners.
 * Call this when unmounting the application (e.g. on page unload).
 * Note: this removes the GLOBAL visibilitychange, watchdog and
 * page-lifecycle listeners for the rest of the page lifetime — for user
 * sign-out use cleanupUserRefreshState instead.
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

  // Clean up auto-cleanup listeners (prevent memory leaks)
  if (autoCleanupHandler && isBrowserEnvironment()) {
    globalThis.removeEventListener("beforeunload", autoCleanupHandler);
    globalThis.removeEventListener("pagehide", autoCleanupHandler);
    autoCleanupHandler = undefined;
  }

  // Clean up per-user refresh state
  cleanupUserRefreshState(username);
}
