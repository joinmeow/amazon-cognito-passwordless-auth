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
  retrieveTokensForRefresh,
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
import { scheduleRefresh, cleanupUserRefreshState } from "./refresh.js";
import { computeClockDriftMs, redactSecret } from "./util.js";
import { handleDeviceConfirmation } from "./device.js";
import { withLock, LockTimeoutError } from "./lock.js";
import { parseJwtPayload } from "./util.js";
import { CognitoAccessTokenPayload } from "./jwt-model.js";

// Prevent duplicate refresh scheduling within this time window
const REFRESH_DEDUPLICATION_WINDOW_MS = 300000; // 5 minutes

// Delay initial refresh scheduling for fresh logins
const FRESH_LOGIN_REFRESH_DELAY_MS = 120000; // 2 minutes

// Track active refresh schedules to prevent duplicate scheduling
// Key: username, Value: { scheduledAt: timestamp, abortController: AbortController, refreshToken: string, accessToken: string }
const activeRefreshSchedules = new Map<
  string,
  {
    scheduledAt: number;
    abortController: AbortController;
    refreshToken: string;
    accessToken: string;
    /** Handle for the fresh-login deferral timer, so it can be cancelled if
     * the schedule is replaced or the user signs out before it fires */
    deferralTimer?: ReturnType<typeof setTimeout>;
  }
>();

/**
 * Storage key of the sign-out tombstone. signOut writes it BEFORE removing
 * the session keys; the refresh path checks it immediately before and after
 * writing refreshed tokens back, so a sign-out racing an in-flight refresh
 * stays signed out in every interleaving. A fresh sign-in clears it.
 */
function signedOutTombstoneKey(clientId: string, username: string) {
  return `Passwordless.${clientId}.${username}.signedOutAt`;
}

/**
 * Remove the per-user session keys from storage. Shared by signOut's
 * teardown and the refresh path's compensating cleanup (when a sign-out
 * lands inside the refresh's check-to-write window). Deliberately does NOT
 * remove the sign-out tombstone or the device key.
 */
async function removeSessionKeysFromStorage(username: string) {
  const { clientId, storage } = configure();
  const amplifyKeyPrefix = `CognitoIdentityServiceProvider.${clientId}`;
  const customKeyPrefix = `Passwordless.${clientId}`;
  await Promise.all([
    storage.removeItem(`${amplifyKeyPrefix}.${username}.idToken`),
    storage.removeItem(`${amplifyKeyPrefix}.${username}.accessToken`),
    storage.removeItem(`${amplifyKeyPrefix}.${username}.refreshToken`),
    storage.removeItem(`${amplifyKeyPrefix}.${username}.tokenScopesString`),
    storage.removeItem(`${amplifyKeyPrefix}.${username}.userData`),
    storage.removeItem(`${amplifyKeyPrefix}.LastAuthUser`),
    storage.removeItem(`${amplifyKeyPrefix}.${username}.clockDriftMs`),
    storage.removeItem(`${customKeyPrefix}.${username}.authMethod`),
    storage.removeItem(`${customKeyPrefix}.${username}.lastRefreshAttempt`),
    storage.removeItem(`${customKeyPrefix}.${username}.lastRefreshCompleted`),
    // Legacy keys no longer written by current versions, removed for
    // migration hygiene
    storage.removeItem(`${customKeyPrefix}.${username}.expireAt`),
    storage.removeItem(`${customKeyPrefix}.${username}.refreshingTokens`),
    // Note: We do NOT remove deviceKey - it should persist between sessions
  ]);
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
 * @returns The processed tokens (with device key and other metadata)
 */
async function processTokensInternal(
  tokens: TokensFromSignIn | TokensFromRefresh,
  abort?: AbortSignal,
  opts?: {
    /**
     * Set by the refresh path: the session (same user, refresh token
     * present, no sign-out tombstone newer than this timestamp) must still
     * exist in storage immediately before the refreshed tokens are written
     * back — and is re-checked right after the write — so a refresh racing
     * a sign-out can never resurrect the signed-out session.
     */
    sessionMustExistSince?: number;
  }
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
      redactSecret(normalizedTokens.newDeviceMetadata.deviceKey)
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
      `🔄 [Process Tokens] Using existing device key ${redactSecret(normalizedTokens.deviceKey)}, remembered: ${remembered}`
    );
  } else {
    debug?.("🔄 [Process Tokens] No device key available in tokens");
  }
  // We only confirm devices when NewDeviceMetadata is provided by Cognito
  // Never attempt to generate a device key or confirm without explicit metadata

  // 2. Store tokens for persistence
  debug?.("🔄 [Process Tokens] Storing tokens for persistence");

  // Capture client clock drift at token receipt. The access token's `iat` is
  // server-trusted and "now" here ≈ receipt time, so this measures the device's
  // clock offset (not the token's age). Persisting it lets token expiry be
  // evaluated against a skew-corrected clock, so a wrong device clock can't make
  // freshly-issued tokens look expired and trap the user in a logout loop.
  const clockDriftMs = computeClockDriftMs(normalizedTokens.accessToken);
  normalizedTokens.clockDriftMs = clockDriftMs;
  const { clockSkewWarningThresholdMs, onClockSkewDetected } = configure();
  const skewThresholdMs = clockSkewWarningThresholdMs ?? 5 * 60 * 1000;
  if (Math.abs(clockDriftMs) > skewThresholdMs) {
    debug?.(
      `⏰ [Process Tokens] Client clock skew detected: ~${Math.round(
        clockDriftMs / 1000
      )}s vs server (threshold ${Math.round(
        skewThresholdMs / 1000
      )}s). Token expiry will be evaluated against a corrected clock.`
    );
    try {
      onClockSkewDetected?.({
        clockDriftMs,
        thresholdMs: skewThresholdMs,
        username: normalizedTokens.username,
      });
    } catch (err) {
      debug?.("[Process Tokens] onClockSkewDetected callback threw:", err);
    }
  }

  const { clientId: clientIdForGuard, storage: storageForGuard } = configure();
  const tombstoneKey = normalizedTokens.username
    ? signedOutTombstoneKey(clientIdForGuard, normalizedTokens.username)
    : undefined;
  const discardRefreshedTokens = () =>
    new Error(
      "Session was signed out during the token refresh; refreshed tokens discarded"
    );
  if (opts?.sessionMustExistSince !== undefined && tombstoneKey) {
    // Authoritative pre-write check, kept immediately before the write so
    // the remaining race window is the write itself (covered by the
    // post-write compensation below)
    const tombstone = Number(
      (await storageForGuard.getItem(tombstoneKey)) ?? 0
    );
    const lastAuthUser = await storageForGuard.getItem(
      `CognitoIdentityServiceProvider.${clientIdForGuard}.LastAuthUser`
    );
    const storedRefreshToken = lastAuthUser
      ? await storageForGuard.getItem(
          `CognitoIdentityServiceProvider.${clientIdForGuard}.${lastAuthUser}.refreshToken`
        )
      : null;
    if (
      tombstone >= opts.sessionMustExistSince ||
      lastAuthUser !== normalizedTokens.username ||
      !storedRefreshToken
    ) {
      debug?.(
        "🔄 [Process Tokens] Session was signed out before the refreshed tokens could be stored; discarding"
      );
      throw discardRefreshedTokens();
    }
  }

  // Store the already normalized tokens
  await storeTokens(normalizedTokens);

  if (opts?.sessionMustExistSince !== undefined && tombstoneKey) {
    // Compensating post-write check: a sign-out that began inside the tiny
    // pre-check→write window left its tombstone (signOut writes it BEFORE
    // removing keys). Undo our write so the sign-out stays won.
    const tombstone = Number(
      (await storageForGuard.getItem(tombstoneKey)) ?? 0
    );
    if (tombstone >= opts.sessionMustExistSince) {
      debug?.(
        "🔄 [Process Tokens] Sign-out raced the token write; removing the just-written session"
      );
      if (normalizedTokens.username) {
        await removeSessionKeysFromStorage(normalizedTokens.username);
      }
      throw discardRefreshedTokens();
    }
  } else if (tombstoneKey) {
    // Fresh sign-in: clear any stale sign-out tombstone so it cannot
    // interfere with this session's future refreshes
    await storageForGuard.removeItem(tombstoneKey);
  }
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
    // for the SAME access token. New tokens (e.g. just obtained by a refresh)
    // must always get their own schedule: with short-lived access tokens
    // (Cognito allows lifetimes as low as 5 minutes) each refresh completes
    // within the deduplication window, and the previous schedule entry is
    // only cleared after this function returns, so deduplicating on
    // wall-clock age alone would silently prevent the next refresh from
    // ever being scheduled.
    if (
      existingSchedule &&
      existingSchedule.accessToken === normalizedTokens.accessToken &&
      now - existingSchedule.scheduledAt < REFRESH_DEDUPLICATION_WINDOW_MS
    ) {
      debug?.(
        "🔄 [Process Tokens] Refresh already scheduled for this user, skipping duplicate"
      );
      return normalizedTokens;
    }

    // Clear any existing schedule for this user. Skip the abort when the
    // tracked controller is the very one driving THIS call: during an
    // active refresh, refreshTokens passes the schedule's own abort
    // signal back into processTokens, so aborting it here would be a
    // self-abort of the in-flight refresh chain. That fires the old
    // schedule's abort listeners ("Refresh scheduling aborted", which can
    // cancel a pending timer) and leaves the signal permanently aborted,
    // so every later abort-check on that chain (scheduleRefresh's early
    // return, lock acquisition, retry backoff) bails out — and the new
    // tokens can end up without a next refresh. The replacement schedule
    // below is also wired to this same signal, so it must stay live.
    if (existingSchedule?.abortController) {
      if (existingSchedule.abortController.signal !== abort) {
        existingSchedule.abortController.abort();
      }
      // Cancel a still-pending fresh-login deferral so a replaced schedule's
      // timer can't fire and schedule a refresh for stale tokens
      if (existingSchedule.deferralTimer) {
        clearTimeout(existingSchedule.deferralTimer);
      }
      activeRefreshSchedules.delete(normalizedTokens.username);
    }

    const scheduleAbort = new AbortController();

    // Connect external abort signal to our schedule abort controller
    if (abort) {
      abort.addEventListener(
        "abort",
        () => {
          scheduleAbort.abort();
          // Clean up the schedule tracking when aborted, but only if it is
          // still OUR entry — a newer processTokens may have replaced it.
          if (normalizedTokens.username) {
            const current = activeRefreshSchedules.get(
              normalizedTokens.username
            );
            if (current?.abortController === scheduleAbort) {
              if (current.deferralTimer) clearTimeout(current.deferralTimer);
              activeRefreshSchedules.delete(normalizedTokens.username);
            }
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
      accessToken: normalizedTokens.accessToken,
    });

    // Delete the schedule entry only if it is still the one this scheduleFn
    // registered. A completed refresh runs its nested processTokens (which
    // registers the NEXT schedule for the new tokens) BEFORE this tokensCb
    // fires, so an unconditional delete would wipe the replacement entry —
    // leaving the dedup map empty while a timer is armed, and making
    // signOut's targeted abort a no-op for it.
    const clearOwnSchedule = () => {
      if (!normalizedTokens.username) return;
      const current = activeRefreshSchedules.get(normalizedTokens.username);
      if (current?.abortController === scheduleAbort) {
        activeRefreshSchedules.delete(normalizedTokens.username);
      }
    };

    const scheduleFn = () => {
      debug?.("🔄 [Process Tokens] Scheduling token refresh");
      scheduleRefresh({
        abort: scheduleAbort.signal,
        tokensCb: (newTokens) => {
          clearOwnSchedule();
          if (!newTokens) return;
          // We don't need to store tokens here because processTokens will be called
          // for the refresh tokens too, and it will store them.
          return Promise.resolve();
        },
      }).catch((err) => {
        debug?.("❌ [Process Tokens] Failed to schedule token refresh:", err);
        clearOwnSchedule();
      });
    };

    // Defer scheduling only for a genuine fresh login WITH a new device
    // (newDeviceMetadata carrying a deviceKey). The previous `"key" in obj`
    // check was true whenever the property merely existed — including the
    // FIDO2 / hosted-OAuth token objects that set newDeviceMetadata to
    // undefined — so every flow got the 2-minute deferral.
    const freshDeviceKey =
      "newDeviceMetadata" in normalizedTokens
        ? normalizedTokens.newDeviceMetadata?.deviceKey
        : undefined;
    if (!freshDeviceKey) {
      // Not a fresh login with a new device, schedule immediately
      scheduleFn();
    } else {
      // Fresh login with a new device, delay by 2 minutes. Track the timer
      // so a sign-out / replacement within the window can cancel it.
      debug?.(
        "🔄 [Process Tokens] Fresh login detected, deferring token refresh scheduling"
      );
      const deferralTimer = setTimeout(
        scheduleFn,
        FRESH_LOGIN_REFRESH_DELAY_MS
      );
      const entry = activeRefreshSchedules.get(normalizedTokens.username);
      if (entry?.abortController === scheduleAbort) {
        entry.deferralTimer = deferralTimer;
      }
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
  abort?: AbortSignal,
  opts?: Parameters<typeof processTokensInternal>[2]
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
    return await withLock(
      lockKey,
      async () => processTokensInternal(tokens, abort, opts),
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

// Bound the best-effort refresh-token revocation during sign-out so a hung
// network call can never keep the returned `signedOut` promise pending: the
// local teardown (and the app's navigation) has already completed by the time
// revocation runs, so this only caps how long the server-side call may take.
const SIGN_OUT_REVOKE_DEADLINE_MS = 5000;

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
  /**
   * Revoke the refresh token BEFORE removing tokens locally (default: after).
   * Use when sign-out is immediately followed by a navigation (e.g. the
   * hosted UI /logout redirect): revoking first means the network call
   * completes while the page is still alive, and the local sign-out happens
   * right before the navigation — minimizing the window in which the app
   * looks signed out while the Cognito hosted-UI session cookie is still
   * valid (an auto-redirecting app could otherwise silently re-auth as the
   * previous user).
   */
  revokeTokensBeforeLocalRemoval?: boolean;
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

  const amplifyKeyPrefix = `CognitoIdentityServiceProvider.${clientId}`;

  // Resolve the session to tear down. Prefer retrieveTokensForRefresh so a
  // session whose access token has already expired (but is still refreshable)
  // is signed out: retrieveTokens drops expired tokens as a safety net, but the
  // refresh system reads via retrieveTokensForRefresh and would otherwise
  // silently resurrect a session we believe we signed out of. Fall back to
  // retrieveTokens for valid access-only sessions (e.g. OAuth implicit flow)
  // that have no refresh token, and finally to LastAuthUser so an access-only
  // session whose access token has also expired is still cleared. A refresh
  // token, when present, is always surfaced by retrieveTokensForRefresh, so the
  // revocation below still fires whenever there is something to revoke.
  const resolveSignOutSession = async (): Promise<
    { username: string; refreshToken?: string } | undefined
  > => {
    const tokens =
      (await retrieveTokensForRefresh()) ?? (await retrieveTokens());
    if (tokens?.username) {
      return { username: tokens.username, refreshToken: tokens.refreshToken };
    }
    const username = await storage.getItem(`${amplifyKeyPrefix}.LastAuthUser`);
    return username ? { username } : undefined;
  };

  // The local sign-out runs WITHOUT the per-user refresh lock. Holding
  // `.refreshLock` here is what let a single orphaned lock — a tab killed
  // mid-refresh, whose lock record lingers until it goes stale — freeze
  // `/logout` for the ~30s stale-takeover window. The lock was only ever
  // belt-and-suspenders: the sign-out tombstone is authoritative. An in-flight
  // refresh re-checks the tombstone immediately before AND after writing
  // tokens back (processTokens' `sessionMustExistSince` guard) and also
  // re-validates that the session still exists in storage after its network
  // round-trip (refreshTokens), so sign-out wins the race whether or not it
  // holds the lock. Refresh-token revocation is bounded best-effort, after the
  // local teardown.
  const signedOut = (async () => {
    const session = await resolveSignOutSession();
    const userIdentifier = session?.username;
    debug?.("signOut: performing sign-out for user", userIdentifier);

    // Cancel this user's in-memory refresh schedule and per-user state so
    // nothing re-arms a refresh for the session being torn down. In-memory
    // only — no lock required. cleanupUserRefreshState (NOT
    // cleanupRefreshSystem) deliberately preserves the global
    // visibilitychange/watchdog listeners so refresh keeps working for the
    // next user that signs in.
    if (userIdentifier) {
      const activeSchedule = activeRefreshSchedules.get(userIdentifier);
      if (activeSchedule) {
        debug?.("signOut: cancelling active refresh schedule for user");
        activeSchedule.abortController.abort();
        // Also cancel a pending fresh-login deferral so it can't fire and
        // schedule a refresh for the session we are signing out of
        if (activeSchedule.deferralTimer) {
          clearTimeout(activeSchedule.deferralTimer);
        }
        activeRefreshSchedules.delete(userIdentifier);
      }
      cleanupUserRefreshState(userIdentifier);
    }

    try {
      if (abort.signal.aborted) {
        debug?.("Aborting sign-out");
        currentStatus && statusCb?.(currentStatus);
        return;
      }
      if (!session) {
        debug?.("No session in storage to delete");
        props?.tokensRemovedLocallyCb?.();
        statusCb?.("SIGNED_OUT");
        return;
      }
      const { username, refreshToken } = session;
      const revokeRefreshTokenOnce = async () => {
        if (
          refreshToken &&
          !tokenRevocationTracker.has(refreshToken) &&
          !skipTokenRevocation
        ) {
          tokenRevocationTracker.add(refreshToken);
          // Bound the revoke so a hung network call cannot keep `signedOut`
          // pending forever. RevokeToken invalidates the whole token family,
          // so revoking this snapshot also kills any token a racing refresh
          // rotated to.
          const revokeAbort = new AbortController();
          const revokeDeadline = setTimeout(
            () => revokeAbort.abort(),
            SIGN_OUT_REVOKE_DEADLINE_MS
          );
          try {
            await revokeToken({
              abort: revokeAbort.signal,
              refreshToken: refreshToken,
            });
            debug?.("Successfully revoked refresh token");
          } catch (revokeError) {
            debug?.(
              "Error revoking token, but continuing sign-out process:",
              revokeError
            );
          } finally {
            clearTimeout(revokeDeadline);
          }
        }
      };

      // Tombstone FIRST, before revocation and removals: an in-flight refresh
      // re-checks it immediately before AND after writing tokens back, so
      // whichever way the race interleaves, the sign-out wins.
      await storage.setItem(
        signedOutTombstoneKey(clientId, username),
        Date.now().toString()
      );

      // Hosted-UI logout revokes before local removal so the network call
      // completes while the page is still alive (revokeTokensBeforeLocalRemoval).
      if (props?.revokeTokensBeforeLocalRemoval) {
        await revokeRefreshTokenOnce();
      }

      await removeSessionKeysFromStorage(username);
      // Fire the local-removal callback and mark signed-out BEFORE the
      // best-effort revoke: this is the signal the app waits on to navigate
      // away from a protected route, and it must not be gated on a network
      // round-trip (or an orphaned lock).
      props?.tokensRemovedLocallyCb?.();
      statusCb?.("SIGNED_OUT");

      await revokeRefreshTokenOnce();
    } catch (error) {
      if (abort.signal.aborted) return;
      debug?.("Error during sign-out:", error);
      currentStatus && statusCb?.(currentStatus);
      throw error;
    }
  })();
  return {
    signedOut,
    abort: () => abort.abort(),
  };
};
