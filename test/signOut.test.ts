import { configure } from "../client/config.js";
import { signOut } from "../client/common.js";

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

describe("SignOut Lock", () => {
  beforeEach(() => {
    // Configure with in-memory storage and no tokens
    configure({ clientId: "testClient", cognitoIdpEndpoint: "us-west-2" });
  });

  test("should complete immediately when no user is signed in", async () => {
    const { signedOut } = signOut();
    const start = Date.now();
    await signedOut;
    const duration = Date.now() - start;

    expect(duration).toBeLessThan(100);
  });

  test("should complete when another process holds the lock", async () => {
    // First, store minimal user data so signOut knows there's a user
    const { storage } = configure();
    const amplifyKeyPrefix = `CognitoIdentityServiceProvider.testClient`;
    await storage.setItem(`${amplifyKeyPrefix}.LastAuthUser`, "testuser");
    await storage.setItem(
      `${amplifyKeyPrefix}.testuser.accessToken`,
      createValidJWT()
    );
    await storage.setItem(
      `${amplifyKeyPrefix}.testuser.refreshToken`,
      "test-refresh-token"
    );

    // Now block the lock with a non-stale lock to simulate another process
    const userKey = `Passwordless.testClient.testuser.refreshLock`;
    const lockData = {
      id: "test-lock-id",
      timestamp: Date.now(), // Current timestamp so it's not stale
    };
    await storage.setItem(userKey, JSON.stringify(lockData));

    const { signedOut, abort } = signOut();
    
    // Release the lock after a short delay to let signOut proceed
    setTimeout(async () => {
      await storage.removeItem(userKey);
    }, 100);

    // signOut should eventually complete when lock is released
    await expect(signedOut).resolves.toBeUndefined();
  }, 20000); // Increase timeout for lock wait
});
