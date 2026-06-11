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

  test("should return silently when lock is held by another process", async () => {
    // First, store minimal user data so scheduleRefresh knows there's a user
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

    // Now block the lock with a non-stale lock to simulate another tab refreshing
    const userKey = `Passwordless.testClient.testuser.refreshLock`;
    const lockData = {
      id: "test-lock-id",
      timestamp: Date.now(), // Current timestamp so it's not stale
    };
    await storage.setItem(userKey, JSON.stringify(lockData));

    // scheduleRefresh should wait for lock timeout (15s) then return silently
    // This is the expected behavior - it assumes another tab is handling the refresh
    const startTime = Date.now();
    await expect(scheduleRefresh()).resolves.toBeUndefined();
    const duration = Date.now() - startTime;

    // Should have waited approximately 15 seconds before giving up
    expect(duration).toBeGreaterThan(14000);
    expect(duration).toBeLessThan(16000);
  }, 20000); // Increase timeout to handle lock wait

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
