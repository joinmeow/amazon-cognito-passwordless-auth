import { configure } from "../client/config.js";
import { scheduleRefresh, cleanupRefreshSystem } from "../client/refresh.js";
import { storeTokens } from "../client/storage.js";
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

// Mock timer implementation that supports device sleep simulation
class MockTimerEnvironment {
  private currentTime: number;
  private timers: Map<number, { callback: () => void; fireTime: number }> =
    new Map();
  private intervals: Map<
    number,
    { callback: () => void; interval: number; lastRun: number }
  > = new Map();
  private nextId = 1;
  private originalSetTimeout: typeof setTimeout;
  private originalClearTimeout: typeof clearTimeout;
  private originalSetInterval: typeof setInterval;
  private originalClearInterval: typeof clearInterval;
  private originalDateNow: typeof Date.now;

  constructor() {
    this.currentTime = Date.now();
    this.originalSetTimeout = global.setTimeout;
    this.originalClearTimeout = global.clearTimeout;
    this.originalSetInterval = global.setInterval;
    this.originalClearInterval = global.clearInterval;
    this.originalDateNow = Date.now;
  }

  install() {
    // Mock Date.now()
    Date.now = () => this.currentTime;

    // Mock setTimeout
    global.setTimeout = ((callback: () => void, delay: number) => {
      const id = this.nextId++;
      this.timers.set(id, {
        callback,
        fireTime: this.currentTime + delay,
      });
      return id as unknown as NodeJS.Timeout;
    }) as typeof setTimeout;

    // Mock clearTimeout
    global.clearTimeout = ((id: number) => {
      this.timers.delete(id);
    }) as unknown as typeof clearTimeout;

    // Mock setInterval for setTimeoutWallClock
    global.setInterval = ((callback: () => void, interval: number) => {
      const id = this.nextId++;
      this.intervals.set(id, {
        callback,
        interval,
        lastRun: this.currentTime,
      });
      return id as unknown as NodeJS.Timer;
    }) as typeof setInterval;

    // Mock clearInterval
    global.clearInterval = ((id: number) => {
      this.intervals.delete(id);
    }) as unknown as typeof clearInterval;
  }

  uninstall() {
    global.setTimeout = this.originalSetTimeout;
    global.clearTimeout = this.originalClearTimeout;
    global.setInterval = this.originalSetInterval;
    global.clearInterval = this.originalClearInterval;
    Date.now = this.originalDateNow;
  }

  // Simulate normal time progression
  advanceTime(ms: number) {
    const targetTime = this.currentTime + ms;

    while (this.currentTime < targetTime) {
      const step = Math.min(100, targetTime - this.currentTime);
      this.currentTime += step;

      // Fire any timers that should have fired
      for (const [id, timer] of this.timers.entries()) {
        if (timer.fireTime <= this.currentTime) {
          this.timers.delete(id);
          timer.callback();
        }
      }

      // Fire intervals
      for (const interval of this.intervals.values()) {
        if (this.currentTime >= interval.lastRun + interval.interval) {
          interval.lastRun = this.currentTime;
          interval.callback();
        }
      }
    }
  }

  // Simulate device sleep - time jumps forward without firing timers
  simulateDeviceSleep(sleepDurationMs: number) {
    this.currentTime += sleepDurationMs;
    // Don't fire timers during sleep
  }

  // Simulate device wake - process any overdue timers/intervals
  simulateDeviceWake() {
    // Process overdue timers
    for (const [id, timer] of this.timers.entries()) {
      if (timer.fireTime <= this.currentTime) {
        this.timers.delete(id);
        timer.callback();
      }
    }

    // Process overdue intervals (watchdog)
    for (const interval of this.intervals.values()) {
      // Calculate how many times the interval should have fired
      const missedRuns = Math.floor(
        (this.currentTime - interval.lastRun) / interval.interval
      );
      if (missedRuns > 0) {
        interval.lastRun = this.currentTime;
        // Fire once for the accumulated time
        interval.callback();
      }
    }
  }

  getCurrentTime() {
    return this.currentTime;
  }

  getTimerCount() {
    return this.timers.size + this.intervals.size;
  }
}

describe("Device Sleep/Wake Scenarios", () => {
  let fetchMock: jest.Mock;
  let debugLogs: string[] = [];
  let mockStorage: {
    getItem: jest.Mock<Promise<string | null>, [string]>;
    setItem: jest.Mock<Promise<void>, [string, string]>;
    removeItem: jest.Mock<Promise<void>, [string]>;
  };
  let timerEnv: MockTimerEnvironment;

  beforeEach(() => {
    // Create a mock storage
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

    // Install timer mocks
    timerEnv = new MockTimerEnvironment();
    timerEnv.install();

    configure({
      clientId: "testClient",
      cognitoIdpEndpoint: "us-west-2",
      fetch: fetchMock,
      storage: mockStorage,
      debug: (...args: unknown[]) => {
        debugLogs.push(args.map(String).join(" "));
      },
    });
  });

  afterEach(() => {
    // Clean up
    try {
      cleanupRefreshSystem();
    } catch (e) {
      // Ignore cleanup errors
    }
    timerEnv.uninstall();
  });

  describe("Watchdog Timer Behavior", () => {
    test.skip("should detect device sleep and trigger refresh check", async () => {
      const now = timerEnv.getCurrentTime();
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

      // Schedule refresh (starts watchdog)
      await scheduleRefresh();

      // Clear logs
      debugLogs = [];

      // Simulate normal operation for 4 minutes
      timerEnv.advanceTime(4 * 60 * 1000);
      await sleep(100);

      // Simulate device sleep for 20 minutes
      timerEnv.simulateDeviceSleep(20 * 60 * 1000);

      // Simulate device wake
      timerEnv.simulateDeviceWake();
      await sleep(100);

      // Watchdog should detect the large time jump
      const watchdogLog = debugLogs.find(
        (log) => log.includes("Watchdog") || log.includes("wall-clock time")
      );
      expect(watchdogLog).toBeTruthy();

      // Should trigger refresh check
      const refreshCheckLog = debugLogs.find(
        (log) =>
          log.includes("refresh check") || log.includes("scheduling refresh")
      );
      expect(refreshCheckLog).toBeTruthy();
    });

    test.skip("should handle tokens expiring during device sleep", async () => {
      const now = timerEnv.getCurrentTime();
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

      // Clear logs
      debugLogs = [];

      // Simulate device sleep for 15 minutes (tokens will expire)
      timerEnv.simulateDeviceSleep(15 * 60 * 1000);

      // Simulate device wake
      timerEnv.simulateDeviceWake();
      await sleep(200);

      // Should detect expired tokens and refresh
      const expiredLog = debugLogs.find(
        (log) =>
          log.includes("expired") || log.includes("refreshing immediately")
      );
      expect(expiredLog).toBeTruthy();

      // Should have called fetch to refresh
      expect(fetchMock).toHaveBeenCalled();
    });
  });

  describe("Timer Reliability", () => {
    test.skip("should fire refresh timer after device wake if overdue", async () => {
      const now = timerEnv.getCurrentTime();
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

      // Schedule refresh (should be ~8 minutes from now)
      await scheduleRefresh();

      const scheduleLog = debugLogs.find((log) =>
        log.includes("Scheduling token refresh in")
      );
      expect(scheduleLog).toBeTruthy();

      // Clear logs
      debugLogs = [];

      // Advance time 5 minutes (timer not due yet)
      timerEnv.advanceTime(5 * 60 * 1000);
      await sleep(100);

      // Timer should not have fired yet
      expect(fetchMock).not.toHaveBeenCalled();

      // Device sleeps for 10 minutes
      timerEnv.simulateDeviceSleep(10 * 60 * 1000);

      // Wake up - timer is now overdue
      timerEnv.simulateDeviceWake();
      await sleep(200);

      // Timer should fire and trigger refresh
      expect(fetchMock).toHaveBeenCalled();

      const refreshLog = debugLogs.find(
        (log) => log.includes("Token refreshed") || log.includes("refresh")
      );
      expect(refreshLog).toBeTruthy();
    });

    test.skip("should NOT double-refresh if timer fires normally", async () => {
      const now = timerEnv.getCurrentTime();
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

      // Mock successful refresh that returns quickly
      fetchMock.mockResolvedValue({
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

      // Advance time to when refresh should fire (~8 minutes)
      timerEnv.advanceTime(8 * 60 * 1000);
      await sleep(200);

      // Should have refreshed once
      expect(fetchMock).toHaveBeenCalledTimes(1);

      // Clear mock
      fetchMock.mockClear();

      // Advance time a bit more
      timerEnv.advanceTime(1 * 60 * 1000);
      await sleep(100);

      // Should NOT refresh again
      expect(fetchMock).not.toHaveBeenCalled();
    });
  });

  describe("Clock Change Scenarios", () => {
    test.skip("should handle system clock moving backwards", async () => {
      const now = timerEnv.getCurrentTime();
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

      // Schedule refresh
      await scheduleRefresh();

      // Clear logs
      debugLogs = [];

      // Simulate clock moving backwards by 10 minutes
      timerEnv.simulateDeviceSleep(-10 * 60 * 1000); // Negative sleep = clock backwards

      // Advance time normally
      timerEnv.advanceTime(5 * 60 * 1000);
      await sleep(100);

      // Timer behavior depends on implementation
      // It should still work correctly based on wall clock time
      const timerCount = timerEnv.getTimerCount();
      expect(timerCount).toBeGreaterThan(0); // Timer still active
    });
  });
});
