import { configure } from "../client/config.js";
import { scheduleRefresh } from "../client/refresh.js";
import { storeTokens, retrieveTokens } from "../client/storage.js";

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

describe("CRITICAL BUG: Expired Token Handling", () => {
  let fetchMock: jest.Mock;
  let debugLogs: string[] = [];

  beforeEach(() => {
    fetchMock = jest.fn();
    debugLogs = [];

    configure({
      clientId: "testClient",
      cognitoIdpEndpoint: "us-west-2",
      fetch: fetchMock,
      debug: (...args: any[]) => {
        const msg = args.join(" ");
        debugLogs.push(msg);
      },
    });
  });

  test("retrieveTokens drops expired tokens, preventing refresh", async () => {
    const now = Date.now();
    
    // Store expired tokens
    const expiredTokens = {
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

    await storeTokens(expiredTokens);
    
    // Try to retrieve - it will return undefined!
    const retrieved = await retrieveTokens();
    
    console.log("Stored expired tokens, retrieved:", retrieved);
    console.log("Debug logs:", debugLogs.filter(log => log.includes("expiry")));
    
    // This is the bug - expired tokens are dropped
    expect(retrieved).toBeUndefined();
    
    // With the fix, scheduleRefresh should now handle expired tokens
    // Mock successful refresh
    fetchMock.mockResolvedValueOnce({
      ok: true,
      json: async () => ({
        AuthenticationResult: {
          AccessToken: createJWT({
            sub: "user123",
            username: "testuser",
            exp: Math.floor((Date.now() + 3600000) / 1000),
            iat: Math.floor(Date.now() / 1000),
          }),
          RefreshToken: "new-refresh-token",
          ExpiresIn: 3600,
        },
      }),
    });
    
    await scheduleRefresh();
    
    // Should detect expired tokens and refresh immediately
    const scheduleLogs = debugLogs.filter(log => 
      log.includes("expires in") || 
      log.includes("refreshing immediately") ||
      log.includes("Token expires")
    );
    
    console.log("Schedule logs:", scheduleLogs);
    
    // The system should now detect the expired tokens!
    expect(scheduleLogs.length).toBeGreaterThan(0);
    expect(scheduleLogs.some(log => log.includes("refreshing immediately"))).toBe(true);
  });

  test("Valid tokens near expiry DO trigger immediate refresh", async () => {
    const now = Date.now();
    
    // Store tokens that expire in 30 seconds (under 60s threshold)
    const nearExpiryTokens = {
      accessToken: createJWT({
        sub: "user123",
        username: "testuser",
        exp: Math.floor((now + 30000) / 1000), // Expires in 30 seconds
        iat: Math.floor(now / 1000),
      }),
      refreshToken: "test-refresh-token",
      username: "testuser",
      expireAt: new Date(now + 30000), // 30 seconds
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

    await storeTokens(nearExpiryTokens);
    
    // Clear logs
    debugLogs = [];
    
    // This should trigger immediate refresh
    await scheduleRefresh();
    
    // Should see immediate refresh log
    const immediateLog = debugLogs.find(log => 
      log.includes("expires in") && log.includes("refreshing immediately")
    );
    
    console.log("Immediate refresh log:", immediateLog);
    
    expect(immediateLog).toBeTruthy();
    expect(immediateLog).toMatch(/expires in \d+s, refreshing immediately/);
    
    // Wait for refresh to complete
    await new Promise(resolve => setTimeout(resolve, 100));
    
    // Should have called refresh API
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  test("The real-world impact: Users get logged out instead of refreshed", async () => {
    const now = Date.now();
    
    // Simulate a user whose token expired while their device was asleep
    const expiredTokens = {
      accessToken: createJWT({
        sub: "user123",
        username: "testuser",
        exp: Math.floor((now - 600000) / 1000), // Expired 10 minutes ago
        iat: Math.floor((now - 4200000) / 1000), // Issued 70 minutes ago
      }),
      refreshToken: "still-valid-refresh-token", // Refresh tokens last much longer!
      username: "testuser",
      expireAt: new Date(now - 600000),
    };

    await storeTokens(expiredTokens);
    
    // When the app tries to use the tokens...
    const tokens = await retrieveTokens();
    
    // They're gone! User appears logged out even though they have a valid refresh token
    expect(tokens).toBeUndefined();
    
    // The refresh token that could have saved the session is lost
    console.log("User had a valid refresh token but it was dropped with the expired access token!");
  });
});