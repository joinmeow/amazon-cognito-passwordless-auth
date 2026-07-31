import { configure } from "../client/config.js";
import { scheduleRefresh, cleanupUserRefreshState } from "../client/refresh.js";

// Helper to create a JWT for testing; expiry offset in seconds from now
const createJWT = (expOffsetSeconds = 3600) => {
  const enc = (obj: unknown) =>
    btoa(JSON.stringify(obj))
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/, "");
  return `${enc({ alg: "HS256", typ: "JWT" })}.${enc({
    sub: "test-sub",
    username: "testuser",
    exp: Math.floor(Date.now() / 1000) + expOffsetSeconds,
    iat: Math.floor(Date.now() / 1000),
  })}.signature`;
};
const createValidJWT = () => createJWT(3600);

const AMPLIFY_PREFIX = "CognitoIdentityServiceProvider.testClient";
const LOCK_KEY = "Passwordless.testClient.testuser.refreshLock";

// Phase 3: scheduling no longer takes the per-user refresh lock. Arming a
// timer is purely local, in-memory work; only the immediate-refresh branch
// (which delegates to refreshTokens) takes the lock, and it does so itself.
describe("ScheduleRefresh (lock-free scheduling)", () => {
  afterEach(() => {
    // Clear any timer a scheduling test armed so it can't leak across tests.
    cleanupUserRefreshState("testuser");
    jest.useRealTimers();
  });

  test("resolves immediately when no user is signed in", async () => {
    configure({ clientId: "testClient", cognitoIdpEndpoint: "us-west-2" });
    const startTime = Date.now();
    await scheduleRefresh();
    expect(Date.now() - startTime).toBeLessThan(100);
  });

  test("arms a distant refresh without creating or waiting on a cross-tab lock", async () => {
    const debug = jest.fn();
    configure({
      clientId: "testClient",
      cognitoIdpEndpoint: "us-west-2",
      debug,
    });
    const { storage } = configure();
    await storage.setItem(`${AMPLIFY_PREFIX}.LastAuthUser`, "testuser");
    await storage.setItem(
      `${AMPLIFY_PREFIX}.testuser.accessToken`,
      createValidJWT()
    );
    await storage.setItem(
      `${AMPLIFY_PREFIX}.testuser.refreshToken`,
      "test-refresh-token"
    );

    // Another tab holds the refresh lock. Old scheduling waited out its 45s
    // acquisition timeout here; lock-free scheduling must ignore it entirely.
    await storage.setItem(
      LOCK_KEY,
      JSON.stringify({ id: "other-tab", timestamp: Date.now() })
    );

    const start = Date.now();
    await scheduleRefresh();

    expect(Date.now() - start).toBeLessThan(3000);
    const messages = debug.mock.calls.map((args) => String(args[0]));
    // Scheduling neither waited on nor created a lock...
    expect(messages.some((m) => m.includes("waiting for lock"))).toBe(false);
    expect(JSON.parse((await storage.getItem(LOCK_KEY))!).id).toBe("other-tab");
    // ...and a future refresh was armed.
    expect(messages.some((m) => m.includes("Scheduling token refresh"))).toBe(
      true
    );
  });

  test("still acts for a user whose access token is already expired, taking the lock at the refresh step", async () => {
    // Regression: scheduling used to resolve the user via retrieveTokens(),
    // which drops an expired access token, so an expired-but-refreshable
    // session was skipped. It must still act — here, an immediate refresh that
    // serializes through the per-user lock via refreshTokens().
    const debug = jest.fn();
    const fetchMock = jest.fn(
      async (_url: unknown, init?: { headers?: Record<string, string> }) => {
        if (
          init?.headers?.["x-amz-target"]?.endsWith("GetTokensFromRefreshToken")
        ) {
          return {
            ok: true,
            status: 200,
            json: async () => ({
              AuthenticationResult: {
                AccessToken: createJWT(3600),
                IdToken: createJWT(3600),
                ExpiresIn: 3600,
                TokenType: "Bearer",
                RefreshToken: "rotated-refresh-token",
              },
            }),
          };
        }
        return { ok: true, status: 200, json: async () => ({}) };
      }
    );
    configure({
      clientId: "testClient",
      cognitoIdpEndpoint: "us-west-2",
      debug,
      useGetTokensFromRefreshToken: true,
      fetch: fetchMock as unknown as typeof fetch,
    });
    const { storage } = configure();
    await storage.setItem(`${AMPLIFY_PREFIX}.LastAuthUser`, "testuser");
    await storage.setItem(
      `${AMPLIFY_PREFIX}.testuser.accessToken`,
      createJWT(-3600) // expired 1 hour ago
    );
    await storage.setItem(
      `${AMPLIFY_PREFIX}.testuser.refreshToken`,
      "test-refresh-token"
    );

    await scheduleRefresh();

    const messages = debug.mock.calls.map((args) => String(args[0]));
    // Took the immediate-refresh branch (not the "no user" no-op)...
    expect(messages.some((m) => m.includes("refreshing immediately"))).toBe(
      true
    );
    // ...which serializes across tabs through the per-user refresh lock.
    expect(
      messages.some((m) => m.includes("refreshTokens: waiting for lock"))
    ).toBe(true);
  });
});
