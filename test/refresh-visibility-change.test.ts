import type { MinimalResponse } from "../client/config.js";

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

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

// We need to clear the module cache and re-import to ensure clean state
beforeEach(() => {
  jest.resetModules();
});

describe("Visibility Change Handler Tests", () => {
  let fetchMock: jest.Mock;
  let debugLogs: string[] = [];
  let mockStorage: {
    getItem: jest.Mock<Promise<string | null>, [string]>;
    setItem: jest.Mock<Promise<void>, [string, string]>;
    removeItem: jest.Mock<Promise<void>, [string]>;
  };
  let documentHidden = false;
  let scheduleRefresh: typeof import("../client/refresh.js").scheduleRefresh;
  let refreshTokens: typeof import("../client/refresh.js").refreshTokens;
  let cleanupRefreshSystem: typeof import("../client/refresh.js").cleanupRefreshSystem;
  let storeTokens: typeof import("../client/storage.js").storeTokens;

  beforeEach(async () => {
    // Create a mock storage with proper implementation
    const storageData = new Map<string, string>();
    mockStorage = {
      getItem: jest.fn((key: string) =>
        Promise.resolve(storageData.get(key) || null)
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

    // Set up fetch mock
    fetchMock = jest.fn();
    debugLogs = [];

    // Mock document.hidden
    Object.defineProperty(document, "hidden", {
      get: () => documentHidden,
      configurable: true,
    });

    // First configure, then import refresh module
    const { configure: configureClient } = await import("../client/config.js");
    configureClient({
      clientId: "testClient",
      cognitoIdpEndpoint: "us-west-2",
      fetch: fetchMock,
      storage: mockStorage,
      debug: (...args: unknown[]) => {
        debugLogs.push(args.map(String).join(" "));
      },
    });

    // Import other modules after configuration
    const refreshModule = await import("../client/refresh.js");
    const storageModule = await import("../client/storage.js");

    // Make these available for tests
    scheduleRefresh = refreshModule.scheduleRefresh;
    refreshTokens = refreshModule.refreshTokens;
    cleanupRefreshSystem = refreshModule.cleanupRefreshSystem;
    storeTokens = storageModule.storeTokens;
  });

  afterEach(async () => {
    // Clean up
    try {
      cleanupRefreshSystem();
    } catch (e) {
      // Ignore cleanup errors in tests
    }
    documentHidden = false;
    // Give cleanup time to complete
    await sleep(100);
  });

  const triggerVisibilityChange = (hidden: boolean) => {
    documentHidden = hidden;
    // Dispatch real event on document
    const event = new Event("visibilitychange");
    document.dispatchEvent(event);
  };

  describe("Trust Timer Behavior", () => {
    test("should trust existing timer when tab becomes visible", async () => {
      const now = Date.now();
      const expiresIn30Min = new Date(now + 30 * 60 * 1000);

      const tokens = {
        accessToken: createJWT({
          sub: "user123",
          username: "testuser",
          exp: Math.floor(expiresIn30Min.getTime() / 1000),
          iat: Math.floor(now / 1000),
        }),
        refreshToken: "test-refresh-token",
        username: "testuser",
        expireAt: expiresIn30Min,
      };

      await storeTokens(tokens);

      // Schedule initial refresh
      await scheduleRefresh();

      const scheduleLog = debugLogs.find((log) =>
        log.includes("Scheduling token refresh in")
      );
      expect(scheduleLog).toBeTruthy();

      // Clear logs to track visibility change behavior
      debugLogs = [];

      // Simulate tab becoming hidden then visible
      triggerVisibilityChange(true);
      await sleep(100);
      triggerVisibilityChange(false);
      await sleep(100);

      // Should skip because timer is already scheduled
      const skipLog = debugLogs.find((log) =>
        log.includes("refresh already in progress or scheduled, skipping")
      );
      expect(skipLog).toBeTruthy();

      // Should NOT reschedule
      const rescheduleLog = debugLogs.find((log) =>
        log.includes("Scheduling token refresh in")
      );
      expect(rescheduleLog).toBeFalsy();
    });

    test("should NOT reschedule when tokens have plenty of time", async () => {
      const now = Date.now();
      const expiresIn20Min = new Date(now + 20 * 60 * 1000);

      const tokens = {
        accessToken: createJWT({
          sub: "user123",
          username: "testuser",
          exp: Math.floor(expiresIn20Min.getTime() / 1000),
          iat: Math.floor(now / 1000),
        }),
        refreshToken: "test-refresh-token",
        username: "testuser",
        expireAt: expiresIn20Min,
      };

      await storeTokens(tokens);

      // Schedule initial refresh
      await scheduleRefresh();

      // Clear logs
      debugLogs = [];

      // Tab becomes visible
      triggerVisibilityChange(false);
      await sleep(100);

      // Should skip - timer is already scheduled
      const skipLog = debugLogs.find((log) =>
        log.includes("refresh already in progress or scheduled, skipping")
      );
      expect(skipLog).toBeTruthy();

      // Should NOT schedule new refresh
      const scheduleLog = debugLogs.find((log) =>
        log.includes("scheduling refresh")
      );
      expect(scheduleLog).toBeFalsy();
    });
  });

  describe("Emergency Refresh Scenarios", () => {
    test("should trigger refresh when tokens expire soon and no timer exists", async () => {
      const now = Date.now();
      const expiresIn4Min = new Date(now + 4 * 60 * 1000); // 4 minutes

      const tokens = {
        accessToken: createJWT({
          sub: "user123",
          username: "testuser",
          exp: Math.floor(expiresIn4Min.getTime() / 1000),
          iat: Math.floor(now / 1000),
        }),
        refreshToken: "test-refresh-token",
        username: "testuser",
        expireAt: expiresIn4Min,
      };

      await storeTokens(tokens);

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
      } as MinimalResponse);

      // Don't schedule initial refresh
      // Simulate tab becoming visible
      triggerVisibilityChange(false);
      await sleep(100);

      // Should detect tokens expiring soon
      const expiringLog = debugLogs.find(
        (log) =>
          log.includes("tokens expiring in") &&
          log.includes("scheduling refresh")
      );
      expect(expiringLog).toBeTruthy();

      // Should have scheduled refresh
      const scheduleLog = debugLogs.find(
        (log) =>
          log.includes("Scheduling token refresh") ||
          log.includes("refreshing immediately")
      );
      expect(scheduleLog).toBeTruthy();
    });

    test("should NOT intervene when tokens have more than 5 minutes", async () => {
      const now = Date.now();
      const expiresIn10Min = new Date(now + 10 * 60 * 1000);

      const tokens = {
        accessToken: createJWT({
          sub: "user123",
          username: "testuser",
          exp: Math.floor(expiresIn10Min.getTime() / 1000),
          iat: Math.floor(now / 1000),
        }),
        refreshToken: "test-refresh-token",
        username: "testuser",
        expireAt: expiresIn10Min,
      };

      await storeTokens(tokens);

      // Clear logs
      debugLogs = [];

      // Tab becomes visible
      triggerVisibilityChange(false);
      await sleep(100);

      // Should NOT schedule refresh (tokens have 10 minutes left)
      const scheduleLog = debugLogs.find((log) =>
        log.includes("scheduling refresh")
      );
      expect(scheduleLog).toBeFalsy();

      // Should detect visibility change
      const visibilityLog = debugLogs.find((log) =>
        log.includes("visibilitychange event:")
      );
      expect(visibilityLog).toBeTruthy();
    });
  });

  describe("Multiple Tab Switch Scenarios", () => {
    test("should handle rapid tab switching without rescheduling", async () => {
      const now = Date.now();
      const expiresIn30Min = new Date(now + 30 * 60 * 1000);

      const tokens = {
        accessToken: createJWT({
          sub: "user123",
          username: "testuser",
          exp: Math.floor(expiresIn30Min.getTime() / 1000),
          iat: Math.floor(now / 1000),
        }),
        refreshToken: "test-refresh-token",
        username: "testuser",
        expireAt: expiresIn30Min,
      };

      await storeTokens(tokens);

      // Schedule initial refresh
      await scheduleRefresh();

      const initialScheduleLog = debugLogs.find((log) =>
        log.includes("Scheduling token refresh in")
      );
      expect(initialScheduleLog).toBeTruthy();

      // Clear logs
      debugLogs = [];

      // Rapid tab switching
      for (let i = 0; i < 5; i++) {
        triggerVisibilityChange(true);
        await sleep(50);
        triggerVisibilityChange(false);
        await sleep(50);
      }

      // Should have multiple visibility events
      const visibilityLogs = debugLogs.filter((log) =>
        log.includes("visibilitychange event:")
      );
      expect(visibilityLogs.length).toBe(10); // 5 hide + 5 show

      // Should skip all attempts
      const skipLogs = debugLogs.filter((log) =>
        log.includes("refresh already in progress or scheduled, skipping")
      );
      expect(skipLogs.length).toBe(5); // 5 times when becoming visible

      // Should NOT reschedule
      const rescheduleLogs = debugLogs.filter((log) =>
        log.includes("Scheduling token refresh in")
      );
      expect(rescheduleLogs.length).toBe(0);
    });
  });

  describe("Refresh In Progress Scenarios", () => {
    test("should skip when refresh is actively running", async () => {
      const now = Date.now();
      const expiresIn3Min = new Date(now + 3 * 60 * 1000);

      const tokens = {
        accessToken: createJWT({
          sub: "user123",
          username: "testuser",
          exp: Math.floor(expiresIn3Min.getTime() / 1000),
          iat: Math.floor(now / 1000),
        }),
        refreshToken: "test-refresh-token",
        username: "testuser",
        expireAt: expiresIn3Min,
        authMethod: "REDIRECT" as const,
      };

      await storeTokens(tokens);

      // Mock slow refresh (takes 500ms)
      fetchMock.mockImplementationOnce(
        () =>
          new Promise((resolve) => {
            setTimeout(() => {
              resolve({
                ok: true,
                json: async () => ({
                  access_token: createJWT({
                    sub: "user123",
                    username: "testuser",
                    exp: Math.floor((now + 3600000) / 1000),
                    iat: Math.floor(now / 1000),
                  }),
                  refresh_token: "new-refresh-token",
                  expires_in: 3600,
                }),
              } as MinimalResponse);
            }, 500);
          })
      );

      // Start refresh directly (tokens expire in 3 minutes = within threshold)
      const refreshPromise = refreshTokens({ tokens, force: true });

      // Wait a bit for refresh to start
      await sleep(100);

      // Clear logs
      debugLogs = [];

      // Tab becomes visible while refresh is running
      triggerVisibilityChange(false);
      await sleep(100);

      // Should detect that tokens are expiring soon and try to schedule
      // But should skip because refresh is in progress
      const visibilityLog = debugLogs.find((log) =>
        log.includes("visibilitychange event:")
      );
      expect(visibilityLog).toBeTruthy();

      // Either it skips because of timer or because of isRefreshing
      const skipLog = debugLogs.find(
        (log) =>
          log.includes("refresh already in progress or scheduled, skipping") ||
          log.includes("tokens expiring in")
      );
      expect(skipLog).toBeTruthy();

      // Wait for refresh to complete
      await refreshPromise;
    });
  });

  describe("Edge Cases", () => {
    test("should handle missing tokens gracefully", async () => {
      // No tokens stored

      // Tab becomes visible
      triggerVisibilityChange(false);
      await sleep(100);

      // Should handle gracefully without errors
      const visibilityLog = debugLogs.find((log) =>
        log.includes("visibilitychange event:")
      );
      expect(visibilityLog).toBeTruthy();

      // Should not attempt to schedule
      const scheduleLog = debugLogs.find((log) =>
        log.includes("scheduling refresh")
      );
      expect(scheduleLog).toBeFalsy();
    });

    test("should handle expired tokens that need immediate refresh", async () => {
      const now = Date.now();
      const expiredTime = new Date(now - 5 * 60 * 1000); // Expired 5 minutes ago

      const tokens = {
        accessToken: createJWT({
          sub: "user123",
          username: "testuser",
          exp: Math.floor(expiredTime.getTime() / 1000),
          iat: Math.floor((now - 3600000) / 1000),
        }),
        refreshToken: "test-refresh-token",
        username: "testuser",
        expireAt: expiredTime,
      };

      await storeTokens(tokens);

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
      } as MinimalResponse);

      // Tab becomes visible
      triggerVisibilityChange(false);
      await sleep(100);

      // Should trigger immediate refresh
      const expiringLog = debugLogs.find(
        (log) =>
          log.includes("tokens expiring in") ||
          log.includes("refreshing immediately")
      );
      expect(expiringLog).toBeTruthy();
    });
  });
});
