import { configure } from "../client/config.js";
import { scheduleRefresh } from "../client/refresh.js";

// Helper to create a valid JWT for testing
const createValidJWT = () => {
  const header = btoa(JSON.stringify({ alg: "HS256", typ: "JWT" }))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
  const payload = btoa(
    JSON.stringify({
      sub: "test-sub",
      username: "testuser",
      exp: Math.floor(Date.now() / 1000) + 3600, // 1 hour from now
      iat: Math.floor(Date.now() / 1000),
    })
  )
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
  return `${header}.${payload}.signature`;
};

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
});
