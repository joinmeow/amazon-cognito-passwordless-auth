import { configure } from "../client/config.js";
import { scheduleRefresh } from "../client/refresh.js";
import {
  storeTokens,
  retrieveTokens,
  retrieveTokensForRefresh,
} from "../client/storage.js";

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

describe("Expired Token Fix Verification", () => {
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
      },
    });
  });

  test("retrieveTokens still drops expired tokens (expected)", async () => {
    const now = Date.now();
    const expiredTokens = {
      accessToken: createJWT({
        sub: "user123",
        username: "testuser",
        exp: Math.floor((now - 3600000) / 1000),
        iat: Math.floor((now - 7200000) / 1000),
      }),
      refreshToken: "test-refresh-token",
      username: "testuser",
      expireAt: new Date(now - 3600000),
    };

    await storeTokens(expiredTokens);
    const retrieved = await retrieveTokens();

    // This is expected - retrieveTokens drops expired tokens
    expect(retrieved).toBeUndefined();
  });

  test("retrieveTokensForRefresh returns expired tokens (fix)", async () => {
    const now = Date.now();
    const expiredTokens = {
      accessToken: createJWT({
        sub: "user123",
        username: "testuser",
        exp: Math.floor((now - 3600000) / 1000),
        iat: Math.floor((now - 7200000) / 1000),
      }),
      refreshToken: "test-refresh-token",
      username: "testuser",
      expireAt: new Date(now - 3600000),
    };

    await storeTokens(expiredTokens);
    const retrieved = await retrieveTokensForRefresh();

    // This is the fix - retrieveTokensForRefresh returns expired tokens
    expect(retrieved).toBeDefined();
    expect(retrieved?.refreshToken).toBe("test-refresh-token");
    expect(retrieved?.username).toBe("testuser");
    expect(retrieved?.expireAt.getTime()).toBeLessThan(now);
  });

  test("scheduleRefresh now handles expired tokens", async () => {
    const now = Date.now();
    const expiredTokens = {
      accessToken: createJWT({
        sub: "user123",
        username: "testuser",
        exp: Math.floor((now - 3600000) / 1000),
        iat: Math.floor((now - 7200000) / 1000),
      }),
      refreshToken: "test-refresh-token",
      username: "testuser",
      expireAt: new Date(now - 3600000),
    };

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

    await storeTokens(expiredTokens);

    // Clear logs
    debugLogs = [];

    // This should now work with expired tokens
    await scheduleRefresh();

    // Should detect expiry and refresh immediately
    const refreshLog = debugLogs.find((log) =>
      log.includes("refreshing immediately")
    );

    expect(refreshLog).toBeDefined();
    expect(refreshLog).toContain("expires in -");

    // Wait for refresh
    await new Promise((resolve) => setTimeout(resolve, 100));

    // Should have called refresh
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });
});
