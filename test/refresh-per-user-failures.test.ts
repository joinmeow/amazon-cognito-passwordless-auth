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

// Regression coverage for the per-user scheduled-refresh failure backoff:
//  1. The consecutive-failure counter is PER USER (RefreshState), so one
//     user's repeated scheduled-refresh failures don't throttle another
//     user's backoff after a user switch (both independently log "retry 1/5").
//  2. The failure-backoff retry timer is tracked in the per-user state so
//     cleanupUserRefreshState can cancel it — otherwise it fires for a
//     session that has already been signed out / torn down.
//
// TEST ISOLATION: like the other refresh suites in this directory,
// processTokens/scheduleRefresh launch fire-and-forget chains whose hops
// (storage-lock jitter sleeps, poll loops) can outlive the test that started
// them. With static imports a straggler chain re-reads the process-global
// config singleton and operates on the NEXT test's storage/mocks. Each test
// therefore gets a FRESH module graph (jest.resetModules + dynamic imports).
//
// Uses REAL timers throughout (the project's jest config does not enable fake
// timers); a bounded `waitFor` poll awaits the live machinery. Driving the
// scheduled-refresh retry path under FAKE timers is what hangs
// advanceTimersByTimeAsync, so it is deliberately avoided here.

// This `export {}` makes the file an ES module so its top-level declarations
// (configure, createJWT, …) are module-scoped rather than leaking into the
// shared global script scope, where they would collide with the identically
// named top-level bindings in the other dynamic-import refresh suites
// (refresh-bugs.test.ts, process-tokens-scheduling.test.ts) under ts-jest.
export {};

// Records every setTimeoutWallClock cancel handle so the retry-timer
// cancellation can be observed. setupFilesAfterEnv already mocks
// ../client/util.js (client/__tests__/setup.ts); this per-file mock wraps the
// same surface, additionally recording each timer's delay and a spy on its
// cancel function, and re-implements parseJwtPayload to parse the real JWTs
// the tests mint.
type TimerRecord = { delay: number; cancel: jest.Mock };
const timerRecords: TimerRecord[] = [];

jest.mock("../client/util.js", () => {
  const actualUtil = jest.requireActual("../client/util.js");
  return {
    ...(actualUtil as object),
    setTimeoutWallClock: (fn: () => void, delay: number) => {
      const timeoutId = setTimeout(fn, delay);
      const cancel = jest.fn(() => clearTimeout(timeoutId));
      timerRecords.push({ delay, cancel });
      return cancel;
    },
    parseJwtPayload: (token: string) => {
      const [, payload] = token.split(".");
      if (!payload) throw new Error("Invalid token format");
      const base64 = payload.replace(/-/g, "+").replace(/_/g, "/");
      return JSON.parse(atob(base64)) as Record<string, unknown>;
    },
  };
});

let configure: typeof import("../client/config.js").configure;
let scheduleRefresh: typeof import("../client/refresh.js").scheduleRefresh;
let cleanupRefreshSystem: typeof import("../client/refresh.js").cleanupRefreshSystem;
let cleanupUserRefreshState: typeof import("../client/refresh.js").cleanupUserRefreshState;
let storeTokens: typeof import("../client/storage.js").storeTokens;

const TEST_USERNAMES = ["alice", "bob"];

// Upper bound on the dynamic scheduled-refresh delay the tokens below produce
// (≤1s; see shortDelayTokens). A short real wall-clock wait that still takes
// the scheduled-timer path (not the <=60s immediate-refresh path).
const SCHEDULED_REFRESH_DELAY_MS = 1000;
// First failure backoff = 30000 * 2^(1-1) = 30s (see refresh.ts). The retry
// timer is the setTimeoutWallClock call with exactly this delay.
const FIRST_RETRY_BACKOFF_MS = 30000;
// Generous per-test timeout: the test drives REAL timers + the live storage-
// lock machinery, which can stretch under full-suite parallel CPU contention.
// Normal runtime is well under 15s; this leaves a large margin so a loaded
// machine can't flake it (a tighter 20s budget was observed to be exceeded
// under maximal parallel load).
const TEST_TIMEOUT_MS = 45000;

// waitFor's internal budget must stay below the jest test timeout so a genuine
// hang surfaces as this clearer error, not an opaque jest timeout.
const waitFor = async (predicate: () => boolean, timeoutMs = 30000) => {
  const start = Date.now();
  while (!predicate()) {
    if (Date.now() - start > timeoutMs) {
      throw new Error("Timed out waiting for condition");
    }
    await new Promise((resolve) => setTimeout(resolve, 25));
  }
};

const createJWT = (claims: Record<string, unknown>) => {
  const enc = (obj: unknown) =>
    btoa(JSON.stringify(obj))
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/, "");
  return `${enc({ alg: "HS256", typ: "JWT" })}.${enc(claims)}.signature`;
};

/**
 * Tokens whose access-token claims make scheduleRefresh arm its standard
 * scheduled-refresh timer with a small (≤1s) delay, while keeping
 * timeUntilExpiry comfortably ABOVE the 60s immediate-refresh threshold so
 * sub-second timing can never tip the call into the immediate path (which
 * does not touch the failure counter). Both timeUntilExpiry AND the buffer are
 * derived from the access token's whole-second iat/exp claims
 * (retrieveTokensForRefresh recomputes expireAt from `exp`, so a ms-precise
 * `expireAt` field would be ignored — 1s is the achievable delay floor):
 *   timeUntilExpiry = exp - now ∈ (120s, 121s]   (>> 60s threshold)
 *   lifetime        = exp - iat = 400s → buffer = max(60s, min(0.3*400s, 15m))
 *                                                = 120s
 *   refreshDelay    = timeUntilExpiry - 120s ∈ (0, 1s]
 */
const shortDelayTokens = (username: string) => {
  const nowSec = Math.floor(Date.now() / 1000);
  const exp = nowSec + 121;
  const iat = exp - 400;
  return {
    accessToken: createJWT({ sub: username, username, exp, iat }),
    refreshToken: `${username}-refresh-token`,
    username,
    expireAt: new Date(exp * 1000),
  };
};

describe("Per-user scheduled-refresh failure backoff", () => {
  let fetchMock: jest.Mock;
  let debugLogs: string[];
  let mockStorage: {
    getItem: jest.Mock<Promise<string | null>, [string]>;
    setItem: jest.Mock<Promise<void>, [string, string]>;
    removeItem: jest.Mock<Promise<void>, [string]>;
  };

  beforeEach(async () => {
    jest.resetModules();
    timerRecords.length = 0;
    ({ configure } = await import("../client/config.js"));
    ({
      scheduleRefresh,
      cleanupRefreshSystem,
      cleanupUserRefreshState,
    } = await import("../client/refresh.js"));
    ({ storeTokens } = await import("../client/storage.js"));

    jest.clearAllMocks();

    // Always reject the refresh round-trip. A non-network error message means
    // getTokensFromRefreshToken fails immediately (no internal network retry).
    fetchMock = jest.fn(() =>
      Promise.reject(new Error("Simulated refresh failure"))
    );

    const storageData = new Map<string, string>();
    mockStorage = {
      getItem: jest.fn((key: string) =>
        Promise.resolve(storageData.get(key) ?? null)
      ),
      setItem: jest.fn((key: string, value: string) => {
        storageData.set(key, value);
        return Promise.resolve();
      }),
      removeItem: jest.fn((key: string) => {
        storageData.delete(key);
        return Promise.resolve();
      }),
    };

    // Per-test log array captured by value: a straggler chain from a previous
    // test holds the previous closure and writes into its own discarded array.
    const logs: string[] = [];
    debugLogs = logs;
    configure({
      clientId: "testClient",
      cognitoIdpEndpoint: "us-west-2",
      fetch: fetchMock,
      storage: mockStorage,
      debug: (...args: unknown[]) => {
        logs.push(args.map(String).join(" "));
      },
    });
  });

  afterEach(async () => {
    for (const username of TEST_USERNAMES) {
      cleanupUserRefreshState(username);
    }
    cleanupRefreshSystem();
    // Let any just-settling chain run its final hops against this (now torn
    // down) module graph before the next test replaces it.
    await new Promise((resolve) => setTimeout(resolve, 0));
  });

  test("a second user's first failure logs 'retry 1/5', not '2/5' (counter is per-user, not global)", async () => {
    // Storage tracks a single LastAuthUser, so we exercise the two users
    // SEQUENTIALLY (a user switch): alice fails once, then bob — the exact
    // scenario the fix targets. With a module-global counter bob's first
    // failure would log "retry 2/5" (inheriting alice's count); per-user it
    // must be "retry 1/5".

    // --- alice: drive one failing scheduled refresh ---
    await storeTokens(shortDelayTokens("alice"));
    await scheduleRefresh();
    await waitFor(() =>
      debugLogs.some((l) => l.includes("Scheduling retry"))
    );
    // alice's first (and, since the 30s retry timer hasn't fired, only)
    // failure must be retry 1/5.
    const afterAlice = debugLogs.filter((l) =>
      l.includes("Scheduling retry")
    );
    expect(afterAlice.every((l) => l.includes("Scheduling retry 1/5"))).toBe(
      true
    );
    const aliceRetryCount = afterAlice.length;

    // Cancel alice's armed 30s retry timer so her chain can't add more retry
    // logs while we drive bob (deterministic isolation of the two users).
    cleanupUserRefreshState("alice");

    // --- bob: user switch, then one failing scheduled refresh ---
    await storeTokens(shortDelayTokens("bob"));
    await scheduleRefresh();
    // Wait until bob's failure has produced a NEW retry log beyond alice's.
    await waitFor(
      () =>
        debugLogs.filter((l) => l.includes("Scheduling retry")).length >
        aliceRetryCount
    );

    // The decisive regression signatures, asserted on CONTENT (not on an exact
    // count, which can race under load): with a module-global counter bob's
    // first failure logs "Scheduling retry 2/5"; per-user every failing
    // user's first failure logs "Scheduling retry 1/5".
    const allRetries = debugLogs.filter((l) =>
      l.includes("Scheduling retry")
    );
    expect(allRetries.every((l) => l.includes("Scheduling retry 1/5"))).toBe(
      true
    );
    expect(debugLogs.some((l) => l.includes("Scheduling retry 2/5"))).toBe(
      false
    );
  }, TEST_TIMEOUT_MS);

  test("cleanupUserRefreshState cancels the per-user failure-backoff retry timer", async () => {
    // Only inspect timers created from here on, so a straggler retry timer
    // from another test (timerRecords is module-level) can't be mistaken for
    // this test's.
    const recordsBase = timerRecords.length;

    // One user's scheduled refresh fails and arms a 30s backoff retry timer.
    await storeTokens(shortDelayTokens("alice"));
    await scheduleRefresh();

    // Wait for the failure to arm the retry timer (logged just before it is
    // created).
    await waitFor(() =>
      debugLogs.some((l) => l.includes("Scheduling retry 1/5"))
    );

    // The retry timer is the setTimeoutWallClock call with the first-backoff
    // delay, created during this test. It must exist and not yet be cancelled.
    const retryTimers = timerRecords
      .slice(recordsBase)
      .filter((t) => t.delay === FIRST_RETRY_BACKOFF_MS);
    expect(retryTimers.length).toBe(1);
    const retryTimer = retryTimers[0];
    expect(retryTimer.cancel).not.toHaveBeenCalled();

    // Signing out / tearing down this user must cancel the retry timer so it
    // can never fire (and re-schedule a refresh) for the dead session.
    cleanupUserRefreshState("alice");

    expect(retryTimer.cancel).toHaveBeenCalled();

    // Belt-and-braces: the cancelled retry must not fire a follow-up refresh.
    // (Without cancellation it would re-enter scheduleRefreshUnlocked after
    // the backoff.) The cancel handle clears the underlying setTimeout, so
    // even waiting past a hypothetical short delay yields no further retry.
    const retriesBefore = debugLogs.filter((l) =>
      l.includes("Scheduling retry")
    ).length;
    await new Promise((resolve) => setTimeout(resolve, 50));
    const retriesAfter = debugLogs.filter((l) =>
      l.includes("Scheduling retry")
    ).length;
    expect(retriesAfter).toBe(retriesBefore);
  }, TEST_TIMEOUT_MS);

  test("the scheduled-refresh delay used is the short-lived path (sanity)", async () => {
    // Guards the token tuning above: if the delay drifted to <=60s the
    // immediate path would run and the retry-path tests would silently stop
    // covering the backoff. Assert a standard schedule was armed with a
    // sub-2s delay.
    await storeTokens(shortDelayTokens("alice"));
    await scheduleRefresh();

    const scheduled = timerRecords.find(
      (t) => t.delay > 0 && t.delay <= SCHEDULED_REFRESH_DELAY_MS + 2000
    );
    expect(scheduled).toBeDefined();
    expect(
      debugLogs.some((l) => l.includes("Scheduling token refresh"))
    ).toBe(true);
  });

  test("a scheduled refresh that fails AFTER the session is torn down does not arm a retry", async () => {
    // Race window the guard covers: the scheduled timer has fired and the
    // refresh round-trip is in flight, then a sign-out tears the user down,
    // and only THEN does the refresh reject. cleanupUserRefreshState had no
    // armed retry timer to cancel (the failure hadn't happened yet) and the
    // abort listener, if any, already ran; without the guard the catch would
    // arm a fresh backoff retry on the orphaned state, resurrecting refresh
    // scheduling for a dead session.
    const recordsBase = timerRecords.length;

    // A fetch we hold pending and reject on command, so we can tear the session
    // down strictly BETWEEN the timer firing and the refresh rejecting.
    let rejectFetch!: (err: Error) => void;
    let fetchCalled = false;
    const fetchGate = new Promise<never>((_, reject) => {
      rejectFetch = reject;
    });
    fetchMock.mockImplementation(() => {
      fetchCalled = true;
      // A non-network message keeps getTokensFromRefreshToken from doing its
      // own internal retry, so fetch is hit exactly once.
      return fetchGate;
    });

    await storeTokens(shortDelayTokens("alice"));
    await scheduleRefresh();

    // Wait until the scheduled timer fired and the refresh is in flight.
    await waitFor(() => fetchCalled);

    // Sign out mid-flight: deletes alice's state from refreshStateMap.
    cleanupUserRefreshState("alice");

    const retriesBefore = debugLogs.filter((l) =>
      l.includes("Scheduling retry")
    ).length;

    // Now let the in-flight refresh fail. The catch must observe the torn-down
    // state and bail WITHOUT arming a backoff retry.
    rejectFetch(new Error("Simulated refresh failure"));

    // Deterministically wait until the scheduled-refresh catch has actually run
    // (it logs this at the top, before deciding whether to arm a retry). Once
    // it appears, the arm-or-bail decision has been made synchronously, so the
    // assertions below see the final state rather than racing the propagation.
    await waitFor(() =>
      debugLogs.some((l) => l.includes("Error during scheduled refresh"))
    );

    // The substantive behavior: no first-backoff (30s) retry timer was armed
    // after the teardown, and no new retry was logged. (Without the guard, the
    // catch increments the orphaned state's counter, logs "Scheduling retry
    // 1/5", and arms a 30s retry — both fire synchronously inside the same
    // catch that logged the message we just awaited, so they are already
    // visible here if they happened.)
    const retryTimers = timerRecords
      .slice(recordsBase)
      .filter((t) => t.delay === FIRST_RETRY_BACKOFF_MS);
    expect(retryTimers.length).toBe(0);
    const retriesAfter = debugLogs.filter((l) =>
      l.includes("Scheduling retry")
    ).length;
    expect(retriesAfter).toBe(retriesBefore);

    // And the guard logged its bail-out instead.
    expect(
      debugLogs.some((l) =>
        l.includes("Session torn down during the failed refresh")
      )
    ).toBe(true);
  }, TEST_TIMEOUT_MS);
});
