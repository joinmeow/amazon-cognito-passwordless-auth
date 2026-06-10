import { configure } from "../client/config.js";
import { signOut } from "../client/common.js";
import { storeTokens } from "../client/storage.js";

// Helper to create a JWT with arbitrary claims for testing
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

// Helper to create a valid JWT for testing
const createValidJWT = () =>
  createJWT({
    sub: "test-sub",
    username: "testuser",
    exp: Math.floor(Date.now() / 1000) + 3600, // 1 hour from now
    iat: Math.floor(Date.now() / 1000),
  });

describe("SignOut Lock", () => {
  beforeEach(() => {
    // Configure with in-memory storage and no tokens
    configure({ clientId: "testClient", cognitoIdpEndpoint: "us-west-2" });
  });

  test("should complete immediately when no user is signed in", async () => {
    const { signedOut } = signOut();
    const start = Date.now();
    await signedOut;
    const duration = Date.now() - start;

    expect(duration).toBeLessThan(100);
  });

  test("should complete when another process holds the lock", async () => {
    // First, store minimal user data so signOut knows there's a user
    const { storage } = configure();
    const amplifyKeyPrefix = `CognitoIdentityServiceProvider.testClient`;
    await storage.setItem(`${amplifyKeyPrefix}.LastAuthUser`, "testuser");
    await storage.setItem(
      `${amplifyKeyPrefix}.testuser.accessToken`,
      createValidJWT()
    );
    await storage.setItem(
      `${amplifyKeyPrefix}.testuser.refreshToken`,
      "test-refresh-token"
    );

    // Now block the lock with a non-stale lock to simulate another process
    const userKey = `Passwordless.testClient.testuser.refreshLock`;
    const lockData = {
      id: "test-lock-id",
      timestamp: Date.now(), // Current timestamp so it's not stale
    };
    await storage.setItem(userKey, JSON.stringify(lockData));

    const { signedOut } = signOut();

    // Release the lock after a short delay to let signOut proceed
    setTimeout(async () => {
      await storage.removeItem(userKey);
    }, 100);

    // signOut should eventually complete when lock is released
    await expect(signedOut).resolves.toBeUndefined();
  }, 20000); // Increase timeout for lock wait

  test("should remove all per-user Passwordless keys from storage", async () => {
    // Use an enumerable in-memory storage so we can assert on leftover keys
    const backing = new Map<string, string>();
    configure({
      clientId: "testClient",
      cognitoIdpEndpoint: "us-west-2",
      storage: {
        getItem: (key: string) => backing.get(key) ?? null,
        setItem: (key: string, value: string) => {
          backing.set(key, value);
        },
        removeItem: (key: string) => {
          backing.delete(key);
        },
      },
    });
    const { storage } = configure();

    // Populate everything the library writes for a signed-in user
    const amplifyKeyPrefix = `CognitoIdentityServiceProvider.testClient`;
    const customKeyPrefix = `Passwordless.testClient`;
    await storage.setItem(`${amplifyKeyPrefix}.LastAuthUser`, "testuser");
    await storage.setItem(
      `${amplifyKeyPrefix}.testuser.accessToken`,
      createValidJWT()
    );
    await storage.setItem(`${amplifyKeyPrefix}.testuser.idToken`, "id-token");
    await storage.setItem(
      `${amplifyKeyPrefix}.testuser.refreshToken`,
      "test-refresh-token"
    );
    await storage.setItem(
      `${amplifyKeyPrefix}.testuser.tokenScopesString`,
      "openid"
    );
    await storage.setItem(`${amplifyKeyPrefix}.testuser.userData`, "{}");
    await storage.setItem(`${amplifyKeyPrefix}.testuser.clockDriftMs`, "0");
    await storage.setItem(`${customKeyPrefix}.testuser.authMethod`, "SRP");
    await storage.setItem(
      `${customKeyPrefix}.testuser.lastRefreshAttempt`,
      `${Date.now()}:some-tab-id`
    );
    await storage.setItem(
      `${customKeyPrefix}.testuser.lastRefreshCompleted`,
      Date.now().toString()
    );
    // Device key uses a different shape and must survive sign-out
    const deviceKey = `${customKeyPrefix}.device.testuser`;
    await storage.setItem(deviceKey, JSON.stringify({ deviceKey: "dev-123" }));

    const { signedOut } = signOut({ skipTokenRevocation: true });
    await signedOut;

    const leftoverUserKeys = [...backing.keys()].filter((key) =>
      key.startsWith(`${customKeyPrefix}.testuser.`)
    );
    expect(leftoverUserKeys).toEqual([]);
    const leftoverAmplifyKeys = [...backing.keys()].filter((key) =>
      key.startsWith(amplifyKeyPrefix)
    );
    expect(leftoverAmplifyKeys).toEqual([]);
    // Device key is intentionally preserved between sessions
    expect(backing.has(deviceKey)).toBe(true);
  }, 20000);
});

describe("SignOut with expired access token", () => {
  test("clears storage and revokes refresh token even when access token is expired", async () => {
    const now = Date.now();
    const username = "testuser";
    const refreshToken = "still-valid-refresh-token";

    // fetch mock that captures the RevokeToken call and responds 2xx
    const fetchMock = jest.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => ({}),
    });

    configure({
      clientId: "testClient",
      cognitoIdpEndpoint: "us-west-2",
      fetch: fetchMock,
    });
    const { storage } = configure();

    // Store a session whose access token expired an hour ago but whose refresh
    // token is still valid - the exact state that previously made signOut a
    // no-op (retrieveTokens drops expired tokens), leaving the session
    // resurrectable by the refresh system.
    await storeTokens({
      accessToken: createJWT({
        sub: "user123",
        username,
        scope: "openid",
        exp: Math.floor((now - 3600_000) / 1000), // expired 1h ago
        iat: Math.floor((now - 7200_000) / 1000),
      }),
      idToken: createJWT({
        sub: "user123",
        "cognito:username": username,
        email: "test@example.com",
        exp: Math.floor((now - 3600_000) / 1000),
        iat: Math.floor((now - 7200_000) / 1000),
      }),
      refreshToken,
      authMethod: "SRP",
      expireAt: new Date(now - 3600_000), // expired 1h ago
    });

    const amplifyKeyPrefix = `CognitoIdentityServiceProvider.testClient`;

    // Sanity check: the session is in storage before sign-out.
    expect(await storage.getItem(`${amplifyKeyPrefix}.LastAuthUser`)).toBe(
      username
    );
    expect(
      await storage.getItem(`${amplifyKeyPrefix}.${username}.refreshToken`)
    ).toBe(refreshToken);

    const { signedOut } = signOut();
    await signedOut;

    // All session keys must be gone from storage.
    for (const key of [
      `${amplifyKeyPrefix}.LastAuthUser`,
      `${amplifyKeyPrefix}.${username}.accessToken`,
      `${amplifyKeyPrefix}.${username}.idToken`,
      `${amplifyKeyPrefix}.${username}.refreshToken`,
      `${amplifyKeyPrefix}.${username}.userData`,
    ]) {
      expect(await storage.getItem(key)).toBeNull();
    }

    // The still-valid refresh token must have been revoked server-side.
    const revokeCall = fetchMock.mock.calls.find(([, init]) =>
      init?.headers?.["x-amz-target"]?.endsWith("RevokeToken")
    );
    expect(revokeCall).toBeDefined();
    expect(JSON.parse(revokeCall[1].body)).toEqual(
      expect.objectContaining({ Token: refreshToken, ClientId: "testClient" })
    );
  });

  // Access-only sessions (e.g. OAuth implicit flow) persist a valid access/id
  // token with no refresh token. retrieveTokensForRefresh returns undefined for
  // these, so signOut must still tear them down (no refresh token to revoke).
  test.each([
    { label: "valid", offsetMs: 3600_000 },
    { label: "expired", offsetMs: -3600_000 },
  ])(
    "clears an access-only session with no refresh token ($label access token)",
    async ({ offsetMs }) => {
      const now = Date.now();
      const username = "accessonly";

      const fetchMock = jest.fn().mockResolvedValue({
        ok: true,
        status: 200,
        json: async () => ({}),
      });
      configure({
        clientId: "testClient",
        cognitoIdpEndpoint: "us-west-2",
        fetch: fetchMock,
      });
      const { storage } = configure();

      await storeTokens({
        accessToken: createJWT({
          sub: "user456",
          username,
          scope: "openid",
          exp: Math.floor((now + offsetMs) / 1000),
          iat: Math.floor((now - 7200_000) / 1000),
        }),
        idToken: createJWT({
          sub: "user456",
          "cognito:username": username,
          email: "accessonly@example.com",
          exp: Math.floor((now + offsetMs) / 1000),
          iat: Math.floor((now - 7200_000) / 1000),
        }),
        // no refreshToken
        expireAt: new Date(now + offsetMs),
      });

      const amplifyKeyPrefix = `CognitoIdentityServiceProvider.testClient`;
      expect(await storage.getItem(`${amplifyKeyPrefix}.LastAuthUser`)).toBe(
        username
      );

      const { signedOut } = signOut();
      await signedOut;

      // Session must be cleared even though there was no refresh token.
      for (const key of [
        `${amplifyKeyPrefix}.LastAuthUser`,
        `${amplifyKeyPrefix}.${username}.accessToken`,
        `${amplifyKeyPrefix}.${username}.idToken`,
        `${amplifyKeyPrefix}.${username}.userData`,
      ]) {
        expect(await storage.getItem(key)).toBeNull();
      }

      // Nothing to revoke - no RevokeToken call should be made.
      const revokeCall = fetchMock.mock.calls.find(([, init]) =>
        init?.headers?.["x-amz-target"]?.endsWith("RevokeToken")
      );
      expect(revokeCall).toBeUndefined();
    }
  );
});
