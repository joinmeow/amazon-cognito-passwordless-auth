import { configure } from "../client/config.js";
import { scheduleRefresh } from "../client/refresh.js";
import { storeTokens, retrieveTokens } from "../client/storage.js";
import { processTokens } from "../client/common.js";

// Helper to create JWT tokens
const createJWT = (claims: Record<string, unknown>) => {
  const header = btoa(JSON.stringify({ alg: "HS256", typ: "JWT" }))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
  const payload = btoa(JSON.stringify(claims))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
  return `${header}.${payload}.signature`;
};

describe("Refresh System Bug Hunt", () => {
  let fetchMock: jest.Mock;
  let debugLogs: string[] = [];

  beforeEach(() => {
    fetchMock = jest.fn();
    debugLogs = [];

    configure({
      clientId: "testClient",
      cognitoIdpEndpoint: "us-west-2",
      fetch: fetchMock,
      debug: (...args: unknown[]) => {
        const msg = args.map(String).join(" ");
        debugLogs.push(msg);
        console.log("[DEBUG]", msg);
      },
    });
  });

  test("BUG: scheduleRefresh doesn't actually schedule anything", async () => {
    const now = Date.now();
    const tokens = {
      accessToken: createJWT({
        sub: "user123",
        username: "testuser",
        exp: Math.floor((now + 3600000) / 1000), // 1 hour
        iat: Math.floor(now / 1000),
      }),
      refreshToken: "test-refresh-token",
      username: "testuser",
      expireAt: new Date(now + 3600000),
    };

    await storeTokens(tokens);

    // Call scheduleRefresh
    await scheduleRefresh();

    // Check if it actually scheduled something
    const scheduleLog = debugLogs.find(
      (log) =>
        log.includes("Scheduling token refresh") || log.includes("minutes")
    );

    console.log("All logs:", debugLogs);

    expect(scheduleLog).toBeTruthy();
    expect(debugLogs.length).toBeGreaterThan(0);
  });

  test("BUG: processTokens doesn't schedule refresh", async () => {
    const now = Date.now();
    const tokens = {
      accessToken: createJWT({
        sub: "user123",
        username: "testuser",
        exp: Math.floor((now + 3600000) / 1000),
        iat: Math.floor(now / 1000),
      }),
      idToken: createJWT({
        sub: "user123",
        email: "test@example.com",
        exp: Math.floor((now + 3600000) / 1000),
        iat: Math.floor(now / 1000),
      }),
      refreshToken: "test-refresh-token",
      username: "testuser",
      expireAt: new Date(now + 3600000),
    };

    // Clear logs
    debugLogs = [];

    // Process tokens (simulating post-refresh)
    await processTokens(tokens);

    // Should have scheduled refresh
    const processLogs = debugLogs.filter(
      (log) =>
        log.includes("Process Tokens") ||
        log.includes("Scheduling token refresh") ||
        log.includes("scheduleRefresh")
    );

    console.log("Process logs:", processLogs);

    expect(processLogs.length).toBeGreaterThan(0);

    // Check if tokens were stored
    const stored = await retrieveTokens();
    expect(stored).toBeTruthy();
    expect(stored?.username).toBe("testuser");
  });

  test("BUG: Expired tokens don't trigger immediate refresh", async () => {
    const now = Date.now();
    const tokens = {
      accessToken: createJWT({
        sub: "user123",
        username: "testuser",
        exp: Math.floor((now - 3600000) / 1000), // Expired 1 hour ago
        iat: Math.floor((now - 7200000) / 1000),
      }),
      refreshToken: "test-refresh-token",
      username: "testuser",
      expireAt: new Date(now - 3600000), // Expired
    };

    await storeTokens(tokens);

    // Verify the token was stored with expired time
    const stored = await retrieveTokens();
    console.log("Stored token expireAt:", stored?.expireAt);
    console.log(
      "Time until expiry:",
      stored?.expireAt ? stored.expireAt.getTime() - now : "N/A"
    );

    // Mock successful refresh
    fetchMock.mockResolvedValueOnce({
      ok: true,
      json: async () => ({
        AuthenticationResult: {
          AccessToken: createJWT({
            sub: "user123",
            username: "testuser",
            exp: Math.floor((now + 3600000) / 1000),
            iat: Math.floor(now / 1000),
          }),
          RefreshToken: "new-refresh-token",
          ExpiresIn: 3600,
        },
      }),
    });

    // Clear logs
    debugLogs = [];

    // Schedule refresh for expired tokens
    await scheduleRefresh();

    // Should detect expiry
    const expiryLog = debugLogs.find(
      (log) =>
        log.includes("expires in") ||
        log.includes("refreshing immediately") ||
        log.includes("expired")
    );

    console.log("Expiry logs:", debugLogs);

    expect(expiryLog).toBeTruthy();

    // Wait a bit to see if refresh was attempted
    await new Promise((resolve) => setTimeout(resolve, 100));

    // Should have called fetch for refresh
    expect(fetchMock).toHaveBeenCalled();
  });

  test("BUG: Multiple processTokens calls create duplicate schedules", async () => {
    const now = Date.now();
    const tokens = {
      accessToken: createJWT({
        sub: "user123",
        username: "testuser",
        exp: Math.floor((now + 3600000) / 1000),
        iat: Math.floor(now / 1000),
      }),
      refreshToken: "test-refresh-token",
      username: "testuser",
      expireAt: new Date(now + 3600000),
    };

    // Clear logs
    debugLogs = [];

    // Process tokens multiple times
    await processTokens(tokens);
    const firstCallLogs = [...debugLogs];

    await processTokens(tokens);
    const secondCallLogs = debugLogs.slice(firstCallLogs.length);

    await processTokens(tokens);
    const thirdCallLogs = debugLogs.slice(
      firstCallLogs.length + secondCallLogs.length
    );

    console.log(
      "First call logs:",
      firstCallLogs.filter((log) => log.includes("schedul"))
    );
    console.log(
      "Second call logs:",
      secondCallLogs.filter((log) => log.includes("schedul"))
    );
    console.log(
      "Third call logs:",
      thirdCallLogs.filter((log) => log.includes("schedul"))
    );

    // Should see deduplication in later calls
    const dedupLogs = debugLogs.filter(
      (log) =>
        log.includes("already scheduled") ||
        log.includes("skipping duplicate") ||
        log.includes("Refresh already scheduled")
    );

    expect(dedupLogs.length).toBeGreaterThan(0);
  });
});
