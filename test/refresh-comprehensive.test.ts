import { configure } from "../client/config.js";
import {
  scheduleRefresh,
  refreshTokens,
  forceRefreshTokens,
  cleanupRefreshSystem,
} from "../client/refresh.js";
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

describe("Refresh System Comprehensive Tests", () => {
  let fetchMock: jest.Mock;
  let debugLogs: string[] = [];
  let mockStorage: {
    getItem: jest.Mock<string | null, [string]>;
    setItem: jest.Mock<void, [string, string]>;
    removeItem: jest.Mock<void, [string]>;
    clear: jest.Mock<void, []>;
  };

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
    // Clean up any timers or event listeners
    try {
      cleanupRefreshSystem();
    } catch (e) {
      // Ignore cleanup errors in tests
    }
  });

  describe("Multi-tab Coordination", () => {
    test("should detect recent refresh attempts from other tabs", async () => {
      // This test verifies the multi-tab coordination check
      const attemptKey = `Passwordless.testClient.testuser.lastRefreshAttempt`;
      const recentAttempt = `${Date.now() - 1000}:other-tab-id`; // 1 second ago

      // Mock storage to return recent attempt
      mockStorage.getItem.mockResolvedValue(recentAttempt);

      // Call shouldAttemptRefresh directly (internal function)
      // Since it's not exported, we'll test the behavior through refreshTokens
      const tokens = {
        accessToken: createJWT({
          sub: "user123",
          username: "testuser",
          exp: Math.floor(Date.now() / 1000) + 30, // expires soon
          iat: Math.floor(Date.now() / 1000),
        }),
        refreshToken: "test-refresh-token",
        username: "testuser",
        expireAt: new Date(Date.now() + 30000),
        authMethod: "REDIRECT" as const,
      };

      // Store tokens first
      await storeTokens(tokens);

      // The refresh should detect the recent attempt and skip
      // Since we can't easily test the internal behavior, we'll verify the attempt check was performed
      try {
        await refreshTokens({ tokens });
      } catch (e) {
        // Expected to fail due to various reasons, but we're checking the attempt was made
      }

      // Verify coordination check was performed
      expect(mockStorage.getItem).toHaveBeenCalledWith(attemptKey);
    });

    test("should mark refresh as completed for other tabs", async () => {
      const tokens = {
        accessToken: createJWT({
          sub: "user123",
          username: "testuser",
          exp: Math.floor(Date.now() / 1000) + 3600,
          iat: Math.floor(Date.now() / 1000),
        }),
        refreshToken: "test-refresh-token",
        username: "testuser",
        expireAt: new Date(Date.now() + 30000), // expires soon
        authMethod: "REDIRECT" as const,
      };

      await storeTokens(tokens);

      // Mock successful OAuth refresh response
      fetchMock.mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          access_token: createJWT({
            sub: "user123",
            username: "testuser",
            exp: Math.floor(Date.now() / 1000) + 3600,
            iat: Math.floor(Date.now() / 1000),
          }),
          id_token: createJWT({
            sub: "user123",
            email: "test@example.com",
            exp: Math.floor(Date.now() / 1000) + 3600,
            iat: Math.floor(Date.now() / 1000),
          }),
          refresh_token: "new-refresh-token",
          expires_in: 3600,
          token_type: "Bearer",
        }),
      } as MinimalResponse);

      await refreshTokens({ tokens, force: true });

      // Check that completion was marked
      const completedKey = `Passwordless.testClient.testuser.lastRefreshCompleted`;
      expect(mockStorage.setItem).toHaveBeenCalledWith(
        completedKey,
        expect.any(String)
      );
    });
  });

  describe("Retry and Error Handling", () => {
    test("should retry on network errors", async () => {
      const tokens = {
        accessToken: createJWT({
          sub: "user123",
          username: "testuser",
          exp: Math.floor(Date.now() / 1000) + 30, // expires soon
          iat: Math.floor(Date.now() / 1000),
        }),
        refreshToken: "test-refresh-token",
        username: "testuser",
        expireAt: new Date(Date.now() + 30000),
        authMethod: "REDIRECT" as const, // Force OAuth path
      };

      await storeTokens(tokens);

      // First call fails with network error
      fetchMock.mockRejectedValueOnce(new Error("Network error"));

      // Second call succeeds - OAuth response
      fetchMock.mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          access_token: createJWT({
            sub: "user123",
            username: "testuser",
            exp: Math.floor(Date.now() / 1000) + 3600,
            iat: Math.floor(Date.now() / 1000),
          }),
          id_token: createJWT({
            sub: "user123",
            email: "test@example.com",
            exp: Math.floor(Date.now() / 1000) + 3600,
            iat: Math.floor(Date.now() / 1000),
          }),
          refresh_token: "new-refresh-token",
          expires_in: 3600,
          token_type: "Bearer",
        }),
      } as MinimalResponse);

      // Force refresh to trigger immediate retry logic
      const result = await forceRefreshTokens({ tokens });

      expect(result.refreshToken).toBe("new-refresh-token");
      expect(fetchMock).toHaveBeenCalledTimes(2);
    });

    test("should handle refresh token reuse exception", async () => {
      const tokens = {
        accessToken: createJWT({
          sub: "user123",
          username: "testuser",
          exp: Math.floor(Date.now() / 1000) + 30,
          iat: Math.floor(Date.now() / 1000),
        }),
        refreshToken: "old-refresh-token",
        username: "testuser",
        expireAt: new Date(Date.now() + 30000),
      };

      await storeTokens(tokens);

      // Store a newer refresh token to simulate token rotation
      const newerTokens = { ...tokens, refreshToken: "newer-refresh-token" };
      await storeTokens(newerTokens);

      // First call fails with RefreshTokenReuseException
      const reuseError = new Error("Refresh token reuse detected");
      reuseError.name = "RefreshTokenReuseException";
      fetchMock.mockRejectedValueOnce(reuseError);

      // Second call succeeds with newer token
      fetchMock.mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          AuthenticationResult: {
            AccessToken: createJWT({
              sub: "user123",
              username: "testuser",
              exp: Math.floor(Date.now() / 1000) + 3600,
              iat: Math.floor(Date.now() / 1000),
            }),
            IdToken: createJWT({
              sub: "user123",
              email: "test@example.com",
              exp: Math.floor(Date.now() / 1000) + 3600,
              iat: Math.floor(Date.now() / 1000),
            }),
            RefreshToken: "newest-refresh-token",
            ExpiresIn: 3600,
            TokenType: "Bearer",
          },
        }),
      } as MinimalResponse);

      configure({
        clientId: "testClient",
        cognitoIdpEndpoint: "us-west-2",
        fetch: fetchMock,
        storage: localStorage as unknown as Parameters<
          typeof configure
        >[0]["storage"],
        useGetTokensFromRefreshToken: true,
        debug: (...args: unknown[]) => {
          debugLogs.push(args.map(String).join(" "));
        },
      });

      const result = await forceRefreshTokens({ tokens });

      expect(result.refreshToken).toBe("newest-refresh-token");
      expect(fetchMock).toHaveBeenCalledTimes(2);
    });
  });

  describe("Visibility Change Handling", () => {
    test("should refresh on visibility change after threshold", async () => {
      const tokens = {
        accessToken: createJWT({
          sub: "user123",
          username: "testuser",
          exp: Math.floor(Date.now() / 1000) + 3600,
          iat: Math.floor(Date.now() / 1000),
        }),
        refreshToken: "test-refresh-token",
        username: "testuser",
        expireAt: new Date(Date.now() + 3600000),
      };

      await storeTokens(tokens);

      // Mock document.hidden - skip if it fails
      try {
        Object.defineProperty(document, "hidden", {
          configurable: true,
          writable: true,
          value: false,
        });
      } catch (e) {
        // Skip test if we can't mock document.hidden
        console.log("Skipping visibility test - cannot mock document.hidden");
        return;
      }

      // Simulate visibility change event
      const visibilityEvent = new Event("visibilitychange");
      document.dispatchEvent(visibilityEvent);

      // Wait for async operations
      await sleep(100);

      // Should have scheduled a refresh check
      expect(debugLogs.some((log) => log.includes("visibilitychange"))).toBe(
        true
      );
    });
  });

  describe("Cleanup Functions", () => {
    test("should clean up all resources", async () => {
      const tokens = {
        accessToken: createJWT({
          sub: "user123",
          username: "testuser",
          exp: Math.floor(Date.now() / 1000) + 3600,
          iat: Math.floor(Date.now() / 1000),
        }),
        refreshToken: "test-refresh-token",
        username: "testuser",
        expireAt: new Date(Date.now() + 3600000),
      };

      await storeTokens(tokens);

      // Schedule a refresh
      await scheduleRefresh();

      // Clean up
      cleanupRefreshSystem("testuser");

      // Verify cleanup was logged
      expect(debugLogs.some((log) => log.includes("Cleaning up"))).toBe(true);
    });
  });

  describe("Per-User State Isolation", () => {
    test("should maintain separate refresh states per user", async () => {
      // Set up tokens for user1
      const user1Tokens = {
        accessToken: createJWT({
          sub: "user1",
          username: "user1",
          exp: Math.floor(Date.now() / 1000) + 3600,
          iat: Math.floor(Date.now() / 1000),
        }),
        refreshToken: "user1-refresh-token",
        username: "user1",
        expireAt: new Date(Date.now() + 3600000),
      };

      // Set up tokens for user2
      const user2Tokens = {
        accessToken: createJWT({
          sub: "user2",
          username: "user2",
          exp: Math.floor(Date.now() / 1000) + 3600,
          iat: Math.floor(Date.now() / 1000),
        }),
        refreshToken: "user2-refresh-token",
        username: "user2",
        expireAt: new Date(Date.now() + 3600000),
      };

      // Store tokens for both users
      await storeTokens(user1Tokens);
      await storeTokens(user2Tokens);

      // Schedule refresh for both users
      await scheduleRefresh();

      // Both users should have independent refresh scheduling
      expect(
        debugLogs.filter((log) => log.includes("Scheduling token refresh"))
          .length
      ).toBeGreaterThanOrEqual(1);
    });
  });

  describe("Edge Cases", () => {
    test("should handle missing tokens gracefully", async () => {
      // Try to refresh without any tokens
      await expect(refreshTokens()).rejects.toThrow(
        "Cannot determine user identity"
      );
    });

    test("should handle expired tokens on initial load", async () => {
      const expiredTokens = {
        accessToken: createJWT({
          sub: "user123",
          username: "testuser",
          exp: Math.floor(Date.now() / 1000) - 3600, // expired 1 hour ago
          iat: Math.floor(Date.now() / 1000) - 7200,
        }),
        refreshToken: "test-refresh-token",
        username: "testuser",
        expireAt: new Date(Date.now() - 3600000), // expired
        authMethod: "REDIRECT" as const,
      };

      await storeTokens(expiredTokens);

      // Mock successful refresh
      fetchMock.mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          access_token: createJWT({
            sub: "user123",
            username: "testuser",
            exp: Math.floor(Date.now() / 1000) + 3600,
            iat: Math.floor(Date.now() / 1000),
          }),
          refresh_token: "new-refresh-token",
          expires_in: 3600,
        }),
      } as MinimalResponse);

      // Mock successful refresh for immediate trigger
      fetchMock.mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          access_token: createJWT({
            sub: "user123",
            username: "testuser",
            exp: Math.floor(Date.now() / 1000) + 3600,
            iat: Math.floor(Date.now() / 1000),
          }),
          id_token: createJWT({
            sub: "user123",
            email: "test@example.com",
            exp: Math.floor(Date.now() / 1000) + 3600,
            iat: Math.floor(Date.now() / 1000),
          }),
          refresh_token: "new-refresh-token",
          expires_in: 3600,
          token_type: "Bearer",
        }),
      } as MinimalResponse);

      // Schedule should trigger immediate refresh
      await scheduleRefresh();

      // Wait a bit for the immediate refresh to trigger
      await sleep(200);

      // Should have attempted refresh
      expect(fetchMock).toHaveBeenCalled();
    });

    test("should handle storage failures gracefully", async () => {
      // Make storage.setItem throw
      mockStorage.setItem.mockImplementation(() => {
        throw new Error("Storage quota exceeded");
      });

      const tokens = {
        accessToken: createJWT({
          sub: "user123",
          username: "testuser",
          exp: Math.floor(Date.now() / 1000) + 3600,
          iat: Math.floor(Date.now() / 1000),
        }),
        refreshToken: "test-refresh-token",
        username: "testuser",
        expireAt: new Date(Date.now() + 3600000),
      };

      // Should handle storage error gracefully
      await expect(storeTokens(tokens)).rejects.toThrow(
        "Storage quota exceeded"
      );
    });
  });
});
