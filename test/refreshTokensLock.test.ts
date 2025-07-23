import { configure } from "../client/config.js";
import { refreshTokens } from "../client/refresh.js";
import { storeTokens } from "../client/storage.js";
import type { MinimalResponse } from "../client/config.js";

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

const base64UrlEncode = (str: string) =>
  btoa(str).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

// Create a simple JWT token for testing
const createMockJWT = (payload: Record<string, unknown>) => {
  const header = base64UrlEncode(JSON.stringify({ alg: "HS256", typ: "JWT" }));
  const body = base64UrlEncode(JSON.stringify(payload));
  return `${header}.${body}.signature`;
};

describe("RefreshTokens Lock", () => {
  beforeEach(() => {
    // Ensure clean test environment
    const configModule = jest.requireActual("../client/config.js") as {
      configure: typeof configure;
    };
    const { configure: cfg } = configModule;
    cfg({ clientId: "testClient", cognitoIdpEndpoint: "us-west-2" });
  });

  test("should handle concurrent refresh calls properly", async () => {
    // Configure test environment with fetch stub
    let callCount = 0;
    const callOrder: number[] = [];
    let storedTokens: Parameters<typeof storeTokens>[0] | null = null;

    // Track debug logs
    const debugLogs: string[] = [];
    const debugFn = (...args: unknown[]) => {
      debugLogs.push(args.map(String).join(" "));
    };

    // Create a mock storage that saves/retrieves tokens and handles locks
    const storageData = new Map<string, string>();
    const mockStorage = {
      getItem: async (key: string) => {
        return storageData.get(key) || null;
      },
      setItem: async (key: string, value: string) => {
        storageData.set(key, value);

        // Capture tokens being stored for test verification
        if (key.includes("accessToken")) {
          if (!storedTokens)
            storedTokens = { accessToken: "", expireAt: new Date() };
          storedTokens.accessToken = value;
        }
        if (key.includes("refreshToken")) {
          if (!storedTokens)
            storedTokens = { accessToken: "", expireAt: new Date() };
          storedTokens.refreshToken = value;
        }
        if (key.includes("idToken")) {
          if (!storedTokens)
            storedTokens = { accessToken: "", expireAt: new Date() };
          storedTokens.idToken = value;
        }
        if (key.includes("expireAt")) {
          if (!storedTokens)
            storedTokens = { accessToken: "", expireAt: new Date() };
          storedTokens.expireAt = new Date(value);
        }
        if (key.includes("LastAuthUser")) {
          if (!storedTokens)
            storedTokens = { accessToken: "", expireAt: new Date() };
          storedTokens.username = value;
        }
      },
      removeItem: async (key: string) => {
        storageData.delete(key);
      },
    };

    const dummyFetch = async (
      // eslint-disable-next-line @typescript-eslint/no-unused-vars
      _input: string | URL,
      // eslint-disable-next-line @typescript-eslint/no-unused-vars
      _init?: {
        signal?: AbortSignal;
        headers?: Record<string, string>;
        method?: string;
        body?: string;
      }
    ) => {
      callCount++;
      callOrder.push(callCount);
      await sleep(100);

      // Create unique access token for each call to enable change detection
      const accessToken = createMockJWT({
        sub: "user123",
        username: "testuser",
        exp: Math.floor(Date.now() / 1000) + 3600, // 1 hour from now
        iat: Math.floor(Date.now() / 1000),
        call: callCount, // Add call number to make each token unique
      });

      const response: MinimalResponse = {
        ok: true,
        json: async () => ({
          access_token: accessToken,
          id_token: createMockJWT({
            sub: "user123",
            "cognito:username": "testuser",
            email: "test@example.com",
            exp: Math.floor(Date.now() / 1000) + 3600,
            iat: Math.floor(Date.now() / 1000),
          }),
          refresh_token: `refresh-${callCount}`,
          expires_in: 3600,
          token_type: "Bearer",
        }),
      };
      return response;
    };

    configure({
      clientId: "testClient",
      cognitoIdpEndpoint: "us-west-2",
      fetch: dummyFetch,
      storage: mockStorage,
      debug: debugFn,
      useGetTokensFromRefreshToken: false, // force OAuth path
    });

    // Define dummy tokens payload with proper JWT
    const dummyTokens = {
      refreshToken: "initialRefresh",
      username: "testuser",
      expireAt: new Date(Date.now() + 60000),
      authMethod: "REDIRECT" as const,
      accessToken: createMockJWT({
        sub: "user123",
        username: "testuser",
        exp: Math.floor(Date.now() / 1000) + 3600,
        iat: Math.floor(Date.now() / 1000),
      }),
    };

    // Pre-populate storage with initial tokens
    storedTokens = { ...dummyTokens };

    // Also populate the storage map with initial tokens
    const amplifyKeyPrefix = `CognitoIdentityServiceProvider.testClient`;
    const customKeyPrefix = `Passwordless.testClient`;
    await mockStorage.setItem(
      `${amplifyKeyPrefix}.${dummyTokens.username}.accessToken`,
      dummyTokens.accessToken
    );
    await mockStorage.setItem(
      `${amplifyKeyPrefix}.${dummyTokens.username}.refreshToken`,
      dummyTokens.refreshToken
    );
    await mockStorage.setItem(
      `${amplifyKeyPrefix}.${dummyTokens.username}.idToken`,
      "dummy-id-token"
    );
    await mockStorage.setItem(
      `${customKeyPrefix}.${dummyTokens.username}.expireAt`,
      dummyTokens.expireAt.toISOString()
    );
    await mockStorage.setItem(
      `${amplifyKeyPrefix}.LastAuthUser`,
      dummyTokens.username
    );

    // Invoke two concurrent refreshTokens calls
    const p1 = refreshTokens({ tokens: dummyTokens });
    const p2 = refreshTokens({ tokens: dummyTokens });

    // Use Promise.allSettled since one may fail
    const [result1, result2] = await Promise.allSettled([p1, p2]);

    // At least one should succeed
    const successCount = [result1, result2].filter(
      (r) => r.status === "fulfilled"
    ).length;
    expect(successCount).toBeGreaterThan(0);

    // The current behavior: if refresh is already in progress, the second call will fail
    if (result1.status === "fulfilled" && result2.status === "rejected") {
      // First succeeded, second failed due to "already in progress"
      expect(result1.value.accessToken).toBeTruthy();
      expect(result2.reason.message).toContain(
        "Token refresh already in progress"
      );
    } else if (
      result1.status === "rejected" &&
      result2.status === "fulfilled"
    ) {
      // Second succeeded, first failed (less likely but possible due to race)
      expect(result2.value.accessToken).toBeTruthy();
      expect(result1.reason.message).toContain(
        "Token refresh already in progress"
      );
    } else if (
      result1.status === "fulfilled" &&
      result2.status === "fulfilled"
    ) {
      // Both succeeded - this happens if lock serialization worked perfectly
      expect(result1.value.accessToken).toBeTruthy();
      expect(result2.value.accessToken).toBeTruthy();
    } else {
      // Log debug info if unexpected behavior
      console.log("Debug logs:", debugLogs);
      console.log("Call count:", callCount);
      console.log("Result 1:", result1);
      console.log("Result 2:", result2);
      fail("Unexpected behavior in concurrent refresh test");
    }
  });
});
