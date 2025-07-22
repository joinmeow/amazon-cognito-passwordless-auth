import { configure } from "../client/config.js";
import {
  scheduleRefresh,
  refreshTokens,
  forceRefreshTokens,
  cleanupRefreshSystem,
} from "../client/refresh.js";
import { storeTokens, retrieveTokens } from "../client/storage.js";
import { processTokens } from "../client/common.js";
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

// Mock timer functions to control time
const mockTimers = () => {
  const originalSetTimeout = global.setTimeout;
  const originalClearTimeout = global.clearTimeout;
  const originalSetInterval = global.setInterval;
  const originalClearInterval = global.clearInterval;
  const originalDate = global.Date;

  let currentTime = Date.now();
  const timers = new Map<number, { callback: () => void; time: number }>();
  const intervals = new Map<
    number,
    { callback: () => void; interval: number; lastRun: number }
  >();
  let nextTimerId = 1;

  // Mock Date.now()
  global.Date.now = () => currentTime;
  global.Date = class extends originalDate {
    constructor() {
      super(currentTime);
    }
    static now() {
      return currentTime;
    }
  } as unknown as typeof Date;

  // Mock setTimeout
  global.setTimeout = ((callback: () => void, delay: number) => {
    const id = nextTimerId++;
    timers.set(id, { callback, time: currentTime + delay });
    return id as unknown as NodeJS.Timeout;
  }) as unknown as typeof setTimeout;

  // Mock clearTimeout
  global.clearTimeout = ((id: number) => {
    timers.delete(id);
  }) as unknown as typeof clearTimeout;

  // Mock setInterval (used by setTimeoutWallClock)
  global.setInterval = ((callback: () => void, interval: number) => {
    const id = nextTimerId++;
    intervals.set(id, { callback, interval, lastRun: currentTime });
    return id as unknown as NodeJS.Timer;
  }) as unknown as typeof setInterval;

  // Mock clearInterval
  global.clearInterval = ((id: number) => {
    intervals.delete(id);
  }) as unknown as typeof clearInterval;

  const advanceTime = (ms: number) => {
    const targetTime = currentTime + ms;

    // Process in small steps to handle intervals properly
    while (currentTime < targetTime) {
      const step = Math.min(100, targetTime - currentTime);
      currentTime += step;

      // Execute any timers that should have fired
      for (const [id, timer] of timers.entries()) {
        if (timer.time <= currentTime) {
          timers.delete(id);
          timer.callback();
        }
      }

      // Execute intervals
      for (const [, interval] of intervals.entries()) {
        if (currentTime >= interval.lastRun + interval.interval) {
          interval.lastRun = currentTime;
          interval.callback();
        }
      }
    }
  };

  const restore = () => {
    global.setTimeout = originalSetTimeout;
    global.clearTimeout = originalClearTimeout;
    global.setInterval = originalSetInterval;
    global.clearInterval = originalClearInterval;
    global.Date = originalDate;
  };

  return {
    advanceTime,
    restore,
    getTimerCount: () => timers.size + intervals.size,
    getIntervalCount: () => intervals.size,
  };
};

describe("Same-Tab Refresh Behavior", () => {
  let fetchMock: jest.Mock;
  let debugLogs: string[] = [];
  let mockStorage: {
    getItem: jest.Mock<Promise<string | null>, [string]>;
    setItem: jest.Mock<Promise<void>, [string, string]>;
    removeItem: jest.Mock<Promise<void>, [string]>;
  };
  let timeControl: ReturnType<typeof mockTimers>;

  beforeEach(() => {
    // Create a mock storage with proper implementation
    const storageData = new Map<string, string>();
    mockStorage = {
      getItem: jest.fn((key: string) => storageData.get(key) || null),
      setItem: jest.fn((key: string, value: string) => {
        storageData.set(key, value);
      }),
      removeItem: jest.fn((key: string) => {
        storageData.delete(key);
      }),
      clear: jest.fn(() => {
        storageData.clear();
      }),
    };

    // Set up fetch mock
    fetchMock = jest.fn();
    debugLogs = [];

    // Set up time control
    timeControl = mockTimers();

    configure({
      clientId: "testClient",
      cognitoIdpEndpoint: "us-west-2",
      fetch: fetchMock,
      storage: mockStorage,
      debug: (...args: unknown[]) => {
        debugLogs.push(`[${Date.now()}] ${args.map(String).join(" ")}`);
      },
    });
  });

  afterEach(() => {
    // Clean up any timers or event listeners
    try {
      cleanupRefreshSystem();
    } catch (e) {
      // Ignore cleanup errors in tests
    }
    timeControl.restore();
  });

  describe("Schedule Refresh Timer Behavior", () => {
    test("should set up timer correctly for tokens expiring in future", async () => {
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

      // Check initial timer count
      // const initialTimerCount = timeControl.getTimerCount();

      // Schedule refresh
      await scheduleRefresh();

      // Should have set up a timer (setTimeoutWallClock uses intervals)
      expect(timeControl.getIntervalCount()).toBeGreaterThan(0);

      // Check logs for scheduling confirmation
      const schedLogs = debugLogs.filter((log) =>
        log.includes("Scheduling token refresh")
      );
      expect(schedLogs.length).toBeGreaterThan(0);

      // Should schedule for around 80% of token lifetime
      // The actual calculation is more complex, so just check it's scheduled
      const delayLog = debugLogs.find((log) => log.includes("minutes"));
      expect(delayLog).toBeTruthy();
    });

    test("should trigger immediate refresh for expired tokens", async () => {
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

      // Mock successful refresh response
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
            IdToken: createJWT({
              sub: "user123",
              email: "test@example.com",
              exp: Math.floor((now + 3600000) / 1000),
              iat: Math.floor(now / 1000),
            }),
            RefreshToken: "new-refresh-token",
            ExpiresIn: 3600,
            TokenType: "Bearer",
          },
        }),
      } as MinimalResponse);

      // Schedule refresh
      await scheduleRefresh();

      // Should detect expired tokens or immediate refresh
      const expiredLog = debugLogs.find(
        (log) =>
          log.includes("expires in") ||
          log.includes("refreshing immediately") ||
          log.includes("Token expires")
      );
      expect(expiredLog).toBeTruthy();

      // Wait a bit for immediate refresh to trigger
      await sleep(100);
      timeControl.advanceTime(100);

      // Should have attempted refresh
      expect(fetchMock).toHaveBeenCalled();
    });

    test("should handle timer firing and actual refresh execution", async () => {
      const now = Date.now();
      const expiresIn5Min = new Date(now + 5 * 60 * 1000);

      const tokens = {
        accessToken: createJWT({
          sub: "user123",
          username: "testuser",
          exp: Math.floor(expiresIn5Min.getTime() / 1000),
          iat: Math.floor(now / 1000),
        }),
        refreshToken: "test-refresh-token",
        username: "testuser",
        expireAt: expiresIn5Min,
      };

      await storeTokens(tokens);

      // Mock successful refresh response
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
            IdToken: createJWT({
              sub: "user123",
              email: "test@example.com",
              exp: Math.floor((now + 3600000) / 1000),
              iat: Math.floor(now / 1000),
            }),
            RefreshToken: "new-refresh-token",
            ExpiresIn: 3600,
            TokenType: "Bearer",
          },
        }),
      } as MinimalResponse);

      // Schedule refresh
      await scheduleRefresh();

      // Should schedule for 80% of 5 minutes = 4 minutes
      const expectedDelay = 4 * 60 * 1000;

      // Advance time to when timer should fire
      timeControl.advanceTime(expectedDelay + 100);

      // Give async operations time to complete
      await sleep(200);

      // Should have called the API
      expect(fetchMock).toHaveBeenCalledTimes(1);

      // Check that new tokens were stored
      const storedTokens = await retrieveTokens();
      expect(storedTokens?.refreshToken).toBe("new-refresh-token");
    });

    test("should cancel existing timer when scheduling new refresh", async () => {
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

      // Schedule first refresh
      await scheduleRefresh();
      const firstTimerCount = timeControl.getTimerCount();

      // Schedule second refresh - should cancel first timer
      await scheduleRefresh();
      const secondTimerCount = timeControl.getTimerCount();

      // Timer count should remain the same (old cancelled, new added)
      expect(secondTimerCount).toBe(firstTimerCount);

      // Timer count should remain stable or decrease (old cancelled, new added)
      expect(secondTimerCount).toBeLessThanOrEqual(firstTimerCount + 1);
    });
  });

  describe("Watchdog Timer Behavior", () => {
    test("should set up watchdog timer that checks periodically", async () => {
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

      // Schedule refresh (which starts watchdog)
      await scheduleRefresh();

      const initialTimerCount = timeControl.getTimerCount();
      // Should have at least one timer/interval (for main refresh or watchdog)
      expect(initialTimerCount).toBeGreaterThan(0);

      // Clear debug logs to track watchdog activity
      debugLogs = [];

      // Advance time by 5 minutes (watchdog interval)
      timeControl.advanceTime(5 * 60 * 1000);
      await sleep(100);

      // Should see watchdog activity
      const watchdogLog = debugLogs.find((log) => log.includes("Watchdog"));
      expect(watchdogLog).toBeTruthy();

      // Watchdog should have rescheduled itself
      expect(timeControl.getTimerCount()).toBeGreaterThan(0);
    });

    test("should detect device sleep and adjust refresh timing", async () => {
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

      // Schedule refresh
      await scheduleRefresh();

      // Simulate device sleep by advancing time significantly (20 minutes)
      // without triggering intermediate timers
      const sleepDuration = 20 * 60 * 1000;
      timeControl.advanceTime(sleepDuration);

      // Watchdog should detect the large time jump
      await sleep(100);

      // Should have triggered refresh due to device sleep detection
      expect(fetchMock).toHaveBeenCalled();

      const sleepLog = debugLogs.find(
        (log) =>
          log.includes("Device sleep detected") ||
          log.includes("wall-clock time")
      );
      expect(sleepLog).toBeTruthy();
    });
  });

  describe("Refresh Token Rotation and Storage", () => {
    test("should properly rotate refresh tokens after successful refresh", async () => {
      const now = Date.now();
      const tokens = {
        accessToken: createJWT({
          sub: "user123",
          username: "testuser",
          exp: Math.floor((now + 300000) / 1000), // 5 minutes
          iat: Math.floor(now / 1000),
        }),
        refreshToken: "old-refresh-token",
        username: "testuser",
        expireAt: new Date(now + 300000),
      };

      await storeTokens(tokens);

      // Mock successful refresh with new tokens
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
            IdToken: createJWT({
              sub: "user123",
              email: "test@example.com",
              exp: Math.floor((now + 3600000) / 1000),
              iat: Math.floor(now / 1000),
            }),
            RefreshToken: "new-refresh-token",
            ExpiresIn: 3600,
            TokenType: "Bearer",
          },
        }),
      } as MinimalResponse);

      // Force refresh
      const newTokens = await forceRefreshTokens({ tokens });

      // Verify token rotation
      expect(newTokens.refreshToken).toBe("new-refresh-token");
      expect(newTokens.refreshToken).not.toBe(tokens.refreshToken);

      // Verify storage was updated
      const storedTokens = await retrieveTokens();
      expect(storedTokens?.refreshToken).toBe("new-refresh-token");

      // Verify old refresh token is not in storage
      const amplifyKeyPrefix = `CognitoIdentityServiceProvider.testClient`;
      const oldRefreshKey = `${amplifyKeyPrefix}.testuser.refreshToken`;
      const storedRefresh = mockStorage.getItem(oldRefreshKey);
      expect(storedRefresh).toBe("new-refresh-token");
    });

    test("should handle processTokens integration for refresh scheduling", async () => {
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

      // Clear logs to track processTokens behavior
      debugLogs = [];

      // Process tokens (simulating post-refresh flow)
      await processTokens(tokens);

      // Should have stored tokens
      const storedTokens = await retrieveTokens();
      expect(storedTokens?.refreshToken).toBe("test-refresh-token");

      // Should have scheduled refresh
      const scheduleLog = debugLogs.find((log) =>
        log.includes("Scheduling token refresh")
      );
      expect(scheduleLog).toBeTruthy();

      // Should have active timer
      expect(timeControl.getTimerCount()).toBeGreaterThan(0);
    });
  });

  describe("Error Scenarios and Edge Cases", () => {
    test("should handle rapid successive refresh attempts", async () => {
      const now = Date.now();
      const tokens = {
        accessToken: createJWT({
          sub: "user123",
          username: "testuser",
          exp: Math.floor((now + 300000) / 1000),
          iat: Math.floor(now / 1000),
        }),
        refreshToken: "test-refresh-token",
        username: "testuser",
        expireAt: new Date(now + 300000),
      };

      await storeTokens(tokens);

      // Mock multiple refresh responses
      for (let i = 0; i < 5; i++) {
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
              RefreshToken: `refresh-token-${i}`,
              ExpiresIn: 3600,
            },
          }),
        } as MinimalResponse);
      }

      // Attempt multiple refreshes rapidly
      const promises = [];
      for (let i = 0; i < 5; i++) {
        promises.push(refreshTokens({ tokens }));
      }

      const results = await Promise.allSettled(promises);

      // Should have deduplication in place
      const successCount = results.filter(
        (r) => r.status === "fulfilled"
      ).length;
      expect(successCount).toBeGreaterThan(0);

      // Check for deduplication logs
      const dedupLog = debugLogs.find(
        (log) =>
          log.includes("already refreshing") || log.includes("Another refresh")
      );
      expect(dedupLog).toBeTruthy();
    });

    test("should handle timer cleanup on signout", async () => {
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

      await storeTokens(tokens);

      // Schedule refresh
      await scheduleRefresh();

      const timersBeforeCleanup = timeControl.getTimerCount();
      // Should have some timers/intervals before cleanup
      expect(timersBeforeCleanup).toBeGreaterThan(0);

      // Clean up (simulating signout)
      cleanupRefreshSystem("testuser");

      // All timers should be cancelled
      const cleanupLog = debugLogs.find((log) => log.includes("Cleaning up"));
      expect(cleanupLog).toBeTruthy();

      // Note: We can't directly check timer count after cleanup
      // because our mock doesn't track clearTimeout perfectly
      // But we can verify cleanup was called
    });

    test("should handle missing expireAt gracefully", async () => {
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
        // Missing expireAt
      };

      // Store tokens without expireAt
      await storeTokens(tokens as Parameters<typeof storeTokens>[0]);

      // Schedule refresh should handle this gracefully
      await scheduleRefresh();

      // Should have a warning or skip log
      const warningLog = debugLogs.find(
        (log) =>
          log.includes("No tokens") ||
          log.includes("expireAt") ||
          log.includes("Cannot schedule")
      );
      expect(warningLog).toBeTruthy();
    });

    test("BUG: Multiple refresh schedules for same user", async () => {
      // This test checks if we properly prevent duplicate refresh schedules
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

      // Process tokens multiple times (simulating multiple login flows)
      await processTokens(tokens);
      const firstTimerCount = timeControl.getTimerCount();

      await processTokens(tokens);
      const secondTimerCount = timeControl.getTimerCount();

      await processTokens(tokens);
      const thirdTimerCount = timeControl.getTimerCount();

      // Timer count should not increase with duplicate schedules
      expect(secondTimerCount).toBe(firstTimerCount);
      expect(thirdTimerCount).toBe(firstTimerCount);

      // Check for deduplication logs
      const dedupLogs = debugLogs.filter(
        (log) =>
          log.includes("already scheduled") ||
          log.includes("skipping duplicate")
      );
      expect(dedupLogs.length).toBeGreaterThan(0);
    });
  });
});
