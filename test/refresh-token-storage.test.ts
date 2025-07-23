/**
 * Test to verify that tokens are properly updated in storage after refresh,
 * ensuring the usePasswordless() hook would receive fresh tokens.
 */
import { configure } from "../client/config.js";
import { storeTokens, retrieveTokens } from "../client/storage.js";
import {
  refreshTokens,
  forceRefreshTokens,
  cleanupRefreshSystem,
} from "../client/refresh.js";
import type { MinimalResponse } from "../client/config.js";
import type { TokensFromRefresh } from "../client/model.js";

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

describe("Token Storage Updates After Refresh", () => {
  let fetchMock: jest.Mock;
  let debugLogs: string[] = [];
  let mockStorage: {
    getItem: jest.Mock<Promise<string | null>, [string]>;
    setItem: jest.Mock<Promise<void>, [string, string]>;
    removeItem: jest.Mock<Promise<void>, [string]>;
  };

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
    cleanupRefreshSystem();
  });

  test("should update tokens in storage after refresh", async () => {
    const now = Date.now();
    const expiresIn5Min = new Date(now + 5 * 60 * 1000);

    // Initial tokens (old)
    const oldTokens = {
      accessToken: createJWT({
        sub: "user123",
        username: "testuser",
        exp: Math.floor(expiresIn5Min.getTime() / 1000),
        iat: Math.floor(now / 1000),
        jti: "old-token-id", // Add unique identifier to distinguish tokens
      }),
      idToken: createJWT({
        sub: "user123",
        email: "test@example.com",
        exp: Math.floor(expiresIn5Min.getTime() / 1000),
        iat: Math.floor(now / 1000),
      }),
      refreshToken: "old-refresh-token",
      username: "testuser",
      expireAt: expiresIn5Min,
    };

    // Store initial tokens
    await storeTokens(oldTokens);

    // Verify initial tokens were stored
    let currentTokens = await retrieveTokens();
    expect(currentTokens?.refreshToken).toBe("old-refresh-token");
    const initialAccessToken = currentTokens?.accessToken;

    // Mock successful refresh with NEW tokens
    fetchMock.mockResolvedValueOnce({
      ok: true,
      json: async () => ({
        AuthenticationResult: {
          AccessToken: createJWT({
            sub: "user123",
            username: "testuser",
            exp: Math.floor((now + 3600000) / 1000),
            iat: Math.floor(now / 1000),
            jti: "new-token-id", // Different identifier
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

    // Force a token refresh
    await forceRefreshTokens();

    // Give time for storage operations to complete
    await sleep(100);

    // Retrieve tokens again
    currentTokens = await retrieveTokens();

    // Verify that storage now contains the NEW tokens, not the old ones
    expect(currentTokens).toBeTruthy();
    expect(currentTokens?.accessToken).not.toBe(initialAccessToken);
    expect(currentTokens?.refreshToken).toBe("new-refresh-token");
    expect(currentTokens?.refreshToken).not.toBe("old-refresh-token");

    // Check that the access token contains the new identifier
    const accessTokenPayload = JSON.parse(
      atob(currentTokens!.accessToken.split(".")[1])
    );
    expect(accessTokenPayload.jti).toBe("new-token-id");
  });

  test("should update tokens even during background refresh", async () => {
    const now = Date.now();
    const expiresIn3Min = new Date(now + 3 * 60 * 1000); // Expires soon to trigger refresh

    // Initial tokens
    const oldTokens = {
      accessToken: createJWT({
        sub: "user123",
        username: "testuser",
        exp: Math.floor(expiresIn3Min.getTime() / 1000),
        iat: Math.floor(now / 1000),
        token_use: "access",
        version: 1,
      }),
      idToken: createJWT({
        sub: "user123",
        email: "test@example.com",
        exp: Math.floor(expiresIn3Min.getTime() / 1000),
        iat: Math.floor(now / 1000),
      }),
      refreshToken: "initial-refresh-token",
      username: "testuser",
      expireAt: expiresIn3Min,
    };

    await storeTokens(oldTokens);

    // Verify initial tokens
    let currentTokens = await retrieveTokens();
    expect(currentTokens?.refreshToken).toBe("initial-refresh-token");

    // Mock refresh response
    fetchMock.mockResolvedValueOnce({
      ok: true,
      json: async () => ({
        AuthenticationResult: {
          AccessToken: createJWT({
            sub: "user123",
            username: "testuser",
            exp: Math.floor((now + 3600000) / 1000),
            iat: Math.floor(now / 1000),
            token_use: "access",
            version: 2, // New version
          }),
          IdToken: createJWT({
            sub: "user123",
            email: "test@example.com",
            exp: Math.floor((now + 3600000) / 1000),
            iat: Math.floor(now / 1000),
          }),
          RefreshToken: "updated-refresh-token",
          ExpiresIn: 3600,
          TokenType: "Bearer",
        },
      }),
    } as MinimalResponse);

    // Trigger a background refresh
    let tokensFromCallback: TokensFromRefresh | null = null;
    await refreshTokens({
      tokensCb: async (newTokens) => {
        // Callback is called when tokens are refreshed
        tokensFromCallback = newTokens;
        expect(newTokens).toBeTruthy();
        expect(newTokens?.refreshToken).toBe("updated-refresh-token");
      },
    });

    await sleep(200); // Give time for storage updates

    // Verify storage got the updated tokens
    currentTokens = await retrieveTokens();
    expect(currentTokens?.refreshToken).toBe("updated-refresh-token");

    // Verify the access token was also updated
    const newAccessTokenPayload = JSON.parse(
      atob(currentTokens!.accessToken.split(".")[1])
    );
    expect(newAccessTokenPayload.version).toBe(2);

    // Verify callback got the same tokens that were stored
    expect(tokensFromCallback?.accessToken).toBe(currentTokens?.accessToken);
  });

  test.skip("should handle concurrent refresh attempts properly", async () => {
    const now = Date.now();
    const expiresIn2Min = new Date(now + 2 * 60 * 1000);

    const oldTokens = {
      accessToken: createJWT({
        sub: "user123",
        username: "testuser",
        exp: Math.floor(expiresIn2Min.getTime() / 1000),
        iat: Math.floor(now / 1000),
        seq: 1,
      }),
      refreshToken: "seq-1-refresh",
      username: "testuser",
      expireAt: expiresIn2Min,
    };

    await storeTokens(oldTokens);

    // Mock refresh - multiple times since some attempts might get through
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
              seq: 2,
            }),
            IdToken: createJWT({
              sub: "user123",
              email: "test@example.com",
              exp: Math.floor((now + 3600000) / 1000),
              iat: Math.floor(now / 1000),
            }),
            RefreshToken: "seq-2-refresh",
            ExpiresIn: 3600,
            TokenType: "Bearer",
          },
        }),
      } as MinimalResponse);
    }

    // Attempt multiple refreshes concurrently
    const promises = [];
    for (let i = 0; i < 5; i++) {
      promises.push(refreshTokens());
    }

    const results = await Promise.allSettled(promises);

    // Log results for debugging
    console.log(
      "Concurrent refresh results:",
      results.map((r) => ({
        status: r.status,
        reason:
          r.status === "rejected"
            ? (r as PromiseRejectedResult).reason.message
            : undefined,
      }))
    );

    // At least one should succeed
    const successCount = results.filter((r) => r.status === "fulfilled").length;
    const rejectedCount = results.filter((r) => r.status === "rejected").length;

    expect(successCount).toBeGreaterThanOrEqual(1);
    expect(rejectedCount).toBeGreaterThan(0); // Some should be rejected due to deduplication

    // Check rejected errors are about deduplication
    const rejectedReasons = results
      .filter((r) => r.status === "rejected")
      .map((r) => (r as PromiseRejectedResult).reason.message);

    const dedupeErrors = rejectedReasons.filter(
      (msg) =>
        msg.includes("already in progress") || msg.includes("Another tab")
    );
    expect(dedupeErrors.length).toBeGreaterThan(0);

    // Check final stored tokens
    const finalTokens = await retrieveTokens();
    expect(finalTokens?.refreshToken).toBe("seq-2-refresh");

    // Verify fetch was called at least once but not for every attempt
    expect(fetchMock).toHaveBeenCalled();
    expect(fetchMock).toHaveBeenCalledTimes(1); // Should be deduplicated
  });

  test.skip("should not update tokens after failed refresh", async () => {
    const now = Date.now();
    const expiresIn1Min = new Date(now + 1 * 60 * 1000);

    const oldTokens = {
      accessToken: createJWT({
        sub: "user123",
        username: "testuser",
        exp: Math.floor(expiresIn1Min.getTime() / 1000),
        iat: Math.floor(now / 1000),
        original: true,
      }),
      refreshToken: "about-to-expire-refresh",
      username: "testuser",
      expireAt: expiresIn1Min,
    };

    await storeTokens(oldTokens);

    // Verify tokens were stored
    let currentTokens = await retrieveTokens();
    expect(currentTokens?.refreshToken).toBe("about-to-expire-refresh");
    const originalAccessToken = currentTokens?.accessToken;

    // Mock failed refresh - return a proper response with error
    fetchMock.mockResolvedValueOnce({
      ok: false,
      json: async () => ({
        __type: "NotAuthorizedException",
        message: "Refresh token has expired",
      }),
    } as MinimalResponse);

    // Attempt refresh
    let refreshError: Error | null = null;
    try {
      await forceRefreshTokens();
    } catch (error) {
      refreshError = error as Error;
    }

    await sleep(100);

    // Refresh should have failed
    expect(refreshError).toBeTruthy();
    expect(refreshError?.message).toContain("Refresh token has expired");

    // Tokens should still be the old ones (not updated with stale/invalid data)
    currentTokens = await retrieveTokens();
    expect(currentTokens?.accessToken).toBe(originalAccessToken);

    // Verify the tokens are still the original ones
    const accessTokenPayload = JSON.parse(
      atob(currentTokens!.accessToken.split(".")[1])
    );
    expect(accessTokenPayload.original).toBe(true);
  });

  test("retrieveTokens should always return latest tokens after refresh", async () => {
    const now = Date.now();
    const expiresIn5Min = new Date(now + 5 * 60 * 1000);

    // Store version 1 tokens
    const v1Tokens = {
      accessToken: createJWT({
        sub: "user123",
        username: "testuser",
        exp: Math.floor(expiresIn5Min.getTime() / 1000),
        iat: Math.floor(now / 1000),
        version: 1,
      }),
      idToken: createJWT({
        sub: "user123",
        email: "test@example.com",
        exp: Math.floor(expiresIn5Min.getTime() / 1000),
        iat: Math.floor(now / 1000),
      }),
      refreshToken: "v1-refresh-token",
      username: "testuser",
      expireAt: expiresIn5Min,
    };

    await storeTokens(v1Tokens);

    // Verify v1 tokens
    let tokens = await retrieveTokens();
    expect(tokens?.refreshToken).toBe("v1-refresh-token");

    // Mock refresh to v2
    fetchMock.mockResolvedValueOnce({
      ok: true,
      json: async () => ({
        AuthenticationResult: {
          AccessToken: createJWT({
            sub: "user123",
            username: "testuser",
            exp: Math.floor((now + 3600000) / 1000),
            iat: Math.floor(now / 1000),
            version: 2,
          }),
          IdToken: createJWT({
            sub: "user123",
            email: "test@example.com",
            exp: Math.floor((now + 3600000) / 1000),
            iat: Math.floor(now / 1000),
          }),
          RefreshToken: "v2-refresh-token",
          ExpiresIn: 3600,
          TokenType: "Bearer",
        },
      }),
    } as MinimalResponse);

    // Force refresh
    await forceRefreshTokens();

    // Immediately check tokens
    tokens = await retrieveTokens();
    expect(tokens?.refreshToken).toBe("v2-refresh-token");

    // Check multiple times to ensure consistency
    for (let i = 0; i < 5; i++) {
      await sleep(50);
      const currentTokens = await retrieveTokens();
      expect(currentTokens?.refreshToken).toBe("v2-refresh-token");

      // Verify it's v2
      const payload = JSON.parse(
        atob(currentTokens!.accessToken.split(".")[1])
      );
      expect(payload.version).toBe(2);
    }

    // There should never be a case where we get old tokens after refresh
    expect(tokens?.refreshToken).not.toBe("v1-refresh-token");
  });
});
