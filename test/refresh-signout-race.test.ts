import { configure } from "../client/config.js";
import { refreshTokens } from "../client/refresh.js";
import { storeTokens } from "../client/storage.js";
import { signOut } from "../client/common.js";

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

function createMemoryStorage() {
  const store = new Map<string, string>();
  return {
    getItem: (key: string) => store.get(key) ?? null,
    setItem: (key: string, value: string) => {
      store.set(key, value);
    },
    removeItem: (key: string) => {
      store.delete(key);
    },
  };
}

afterEach(() => {
  jest.useRealTimers();
});

test("a refresh completing after an unlocked sign-out must not resurrect the session", async () => {
  // The exact scenario the signOut lock-timeout fallback creates: the
  // refresh holds the lock with a hung network call, signOut waits out its
  // acquisition timeout and tears the session down WITHOUT the lock, and
  // then the refresh's response finally lands. The refresh must discard
  // its result instead of re-storing the session.
  jest.useFakeTimers();
  const username = "testuser";
  const now = Date.now();

  let releaseRefreshResponse!: (value: unknown) => void;
  const hangingRefreshResponse = new Promise((resolve) => {
    releaseRefreshResponse = resolve;
  });

  const fetchMock = jest.fn(
    (url: unknown, init?: { headers?: Record<string, string> }) => {
      const target = init?.headers?.["x-amz-target"] ?? "";
      if (target.endsWith("GetTokensFromRefreshToken")) {
        // The refresh round-trip hangs until the test releases it
        return hangingRefreshResponse.then(() => ({
          ok: true,
          status: 200,
          json: async () => ({
            AuthenticationResult: {
              AccessToken: createJWT({
                sub: "user123",
                username,
                exp: Math.floor((now + 7200_000) / 1000),
                iat: Math.floor(now / 1000),
              }),
              IdToken: createJWT({
                sub: "user123",
                "cognito:username": username,
                exp: Math.floor((now + 7200_000) / 1000),
                iat: Math.floor(now / 1000),
              }),
              ExpiresIn: 3600,
              TokenType: "Bearer",
              RefreshToken: "rotated-refresh-token",
            },
          }),
        }));
      }
      // RevokeToken and anything else: immediate success
      return Promise.resolve({
        ok: true,
        status: 200,
        json: async () => ({}),
      });
    }
  );

  const storage = createMemoryStorage();
  configure({
    clientId: "testClient",
    cognitoIdpEndpoint: "us-west-2",
    storage,
    fetch: fetchMock as unknown as typeof fetch,
  });

  await storeTokens({
    accessToken: createJWT({
      sub: "user123",
      username,
      scope: "openid",
      exp: Math.floor((now + 3600_000) / 1000),
      iat: Math.floor(now / 1000),
    }),
    idToken: createJWT({
      sub: "user123",
      "cognito:username": username,
      exp: Math.floor((now + 3600_000) / 1000),
      iat: Math.floor(now / 1000),
    }),
    refreshToken: "original-refresh-token",
    authMethod: "SRP",
    expireAt: new Date(now + 3600_000),
  });

  // 1. Start the refresh; it acquires the lock and hangs on the network
  const refreshOutcome: { done: boolean; error?: unknown } = { done: false };
  refreshTokens().then(
    () => {
      refreshOutcome.done = true;
    },
    (error) => {
      refreshOutcome.done = true;
      refreshOutcome.error = error;
    }
  );
  await jest.advanceTimersByTimeAsync(3_000);
  expect(
    fetchMock.mock.calls.some(([, init]) =>
      (init as { headers?: Record<string, string> })?.headers?.[
        "x-amz-target"
      ]?.endsWith("GetTokensFromRefreshToken")
    )
  ).toBe(true);

  // 2. Sign out: the lock is held (and heartbeat-renewed) by the hung
  //    refresh, so signOut waits out its timeout and falls back to the
  //    unlocked teardown
  const signOutOutcome: { done: boolean; error?: unknown } = { done: false };
  signOut().signedOut.then(
    () => {
      signOutOutcome.done = true;
    },
    (error) => {
      signOutOutcome.done = true;
      signOutOutcome.error = error;
    }
  );
  for (let i = 0; i < 90 && !signOutOutcome.done; i++) {
    await jest.advanceTimersByTimeAsync(1000);
  }
  expect(signOutOutcome.done).toBe(true);
  expect(signOutOutcome.error).toBeUndefined();

  const amplifyKeyPrefix = `CognitoIdentityServiceProvider.testClient`;
  expect(storage.getItem(`${amplifyKeyPrefix}.LastAuthUser`)).toBeNull();

  // 3. The hung refresh response finally lands: the refresh must detect
  //    the sign-out and discard its result
  releaseRefreshResponse(undefined);
  for (let i = 0; i < 20 && !refreshOutcome.done; i++) {
    await jest.advanceTimersByTimeAsync(1000);
  }
  expect(refreshOutcome.done).toBe(true);
  expect(refreshOutcome.error).toBeInstanceOf(Error);
  expect(String(refreshOutcome.error)).toContain("signed out during");

  // The session must STAY signed out: nothing re-stored
  expect(storage.getItem(`${amplifyKeyPrefix}.LastAuthUser`)).toBeNull();
  expect(
    storage.getItem(`${amplifyKeyPrefix}.${username}.refreshToken`)
  ).toBeNull();
  expect(
    storage.getItem(`${amplifyKeyPrefix}.${username}.accessToken`)
  ).toBeNull();
});
