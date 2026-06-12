import { configure } from "../client/config.js";
import { scheduleRefresh } from "../client/refresh.js";

// Helper to create a JWT for testing; expiry offset in seconds from now
const createJWT = (expOffsetSeconds = 3600) => {
  const header = btoa(JSON.stringify({ alg: "HS256", typ: "JWT" }))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
  const payload = btoa(
    JSON.stringify({
      sub: "test-sub",
      username: "testuser",
      exp: Math.floor(Date.now() / 1000) + expOffsetSeconds,
      iat: Math.floor(Date.now() / 1000),
    })
  )
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
  return `${header}.${payload}.signature`;
};
const createValidJWT = () => createJWT(3600);

describe("ScheduleRefresh Lock", () => {
  beforeEach(() => {
    // Configure with in-memory storage and no user signed in
    configure({ clientId: "testClient", cognitoIdpEndpoint: "us-west-2" });
  });

  test("should resolve immediately when no user is signed in", async () => {
    const startTime = Date.now();
    await scheduleRefresh();
    const duration = Date.now() - startTime;

    expect(duration).toBeLessThan(100);
  });

  test("should return silently when lock is held by another (renewing) tab", async () => {
    // A lock held by a LIVE tab is renewed via heartbeat; scheduleRefresh
    // waits out its acquisition timeout and then returns silently, assuming
    // the other tab is handling the refresh. (A lock that is NOT renewed
    // goes stale after 30s and is taken over instead — that liveness
    // behavior is covered in lock-liveness.test.ts.)
    jest.useFakeTimers();
    try {
      const { storage } = configure();
      const amplifyKeyPrefix = `CognitoIdentityServiceProvider.testClient`;
      const customKeyPrefix = `Passwordless.testClient`;

      await storage.setItem(`${amplifyKeyPrefix}.LastAuthUser`, "testuser");
      await storage.setItem(
        `${amplifyKeyPrefix}.testuser.accessToken`,
        createValidJWT()
      );
      await storage.setItem(
        `${amplifyKeyPrefix}.testuser.refreshToken`,
        "test-refresh-token"
      );
      await storage.setItem(
        `${customKeyPrefix}.testuser.expireAt`,
        new Date(Date.now() + 3600000).toISOString()
      );

      const userKey = `Passwordless.testClient.testuser.refreshLock`;
      await storage.setItem(
        userKey,
        JSON.stringify({ id: "other-tab-lock", timestamp: Date.now() })
      );
      // The other tab renews its heartbeat, so the lock never goes stale
      const renewer = setInterval(() => {
        void storage.setItem(
          userKey,
          JSON.stringify({ id: "other-tab-lock", timestamp: Date.now() })
        );
      }, 5_000);

      try {
        const outcome: { done: boolean; error?: unknown } = { done: false };
        scheduleRefresh().then(
          () => {
            outcome.done = true;
          },
          (error) => {
            outcome.done = true;
            outcome.error = error;
          }
        );
        // Drive past the lock acquisition timeout (45s)
        for (let i = 0; i < 90 && !outcome.done; i++) {
          await jest.advanceTimersByTimeAsync(1000);
        }

        expect(outcome.done).toBe(true);
        expect(outcome.error).toBeUndefined();
      } finally {
        clearInterval(renewer);
      }
    } finally {
      jest.useRealTimers();
    }
  });

  test("should honor the per-user lock when the access token is expired", async () => {
    // Regression: scheduleRefresh used to derive the lock user via
    // retrieveTokens(), which returns undefined for an expired access token,
    // so the global watchdog/visibilitychange handlers would take the
    // unlocked path and race a concurrent signOut holding the lock.
    const debug = jest.fn();
    configure({
      clientId: "testClient",
      cognitoIdpEndpoint: "us-west-2",
      debug,
    });
    const { storage } = configure();
    const amplifyKeyPrefix = `CognitoIdentityServiceProvider.testClient`;

    await storage.setItem(`${amplifyKeyPrefix}.LastAuthUser`, "testuser");
    await storage.setItem(
      `${amplifyKeyPrefix}.testuser.accessToken`,
      createJWT(-3600) // expired 1 hour ago
    );
    await storage.setItem(
      `${amplifyKeyPrefix}.testuser.refreshToken`,
      "test-refresh-token"
    );

    await scheduleRefresh();

    const messages = debug.mock.calls.map((args) => String(args[0]));
    expect(messages).not.toContain("scheduleRefresh: no user, running unlocked");
    expect(messages).toContain("scheduleRefresh: waiting for lock");
  });
});
