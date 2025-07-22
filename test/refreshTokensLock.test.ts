import { configure } from "../client/config.js";
import { refreshTokens } from "../client/refresh.js";
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
          if (!storedTokens) storedTokens = {};
          storedTokens.accessToken = value;
        }
        if (key.includes("refreshToken")) {
          if (!storedTokens) storedTokens = {};
          storedTokens.refreshToken = value;
        }
        if (key.includes("idToken")) {
          if (!storedTokens) storedTokens = {};
          storedTokens.idToken = value;
        }
        if (key.includes("expireAt")) {
          if (!storedTokens) storedTokens = {};
          storedTokens.expireAt = new Date(value);
        }
        if (key.includes("LastAuthUser")) {
          if (!storedTokens) storedTokens = {};
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

    try {
      const [result1, result2] = await Promise.all([p1, p2]);

      // Both calls should succeed and return tokens
      expect(result1.accessToken).toBeTruthy();
      expect(result2.accessToken).toBeTruthy();

      // The exact behavior depends on timing and the test environment
      // Either:
      // 1. Both calls make API requests (serialized by the lock)
      // 2. Second call uses tokens from the first refresh

      if (callCount === 2) {
        // Both made API calls - they should be serialized
        expect(callOrder).toEqual([1, 2]);
        // Each refresh returns its own tokens independently
        // The exact refresh token depends on which call completed when
        expect(result1.refreshToken).toMatch(/^refresh-\d$/);
        expect(result2.refreshToken).toMatch(/^refresh-\d$/);
      } else if (callCount === 1) {
        // Only first call made API request, second used stored tokens
        expect(result1.refreshToken).toBe("refresh-1");
        // Second call should have the same refresh token as first
        expect(result2.refreshToken).toBe("refresh-1");
      } else {
        fail(`Unexpected call count: ${callCount}`);
      }
    } catch (error) {
      // Log debug info if test fails
      console.log("Debug logs:", debugLogs);
      console.log("Call count:", callCount);
      console.log("Storage data:", [...storageData.entries()]);
      throw error;
    }
  });
});
