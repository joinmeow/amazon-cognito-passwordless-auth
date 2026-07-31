import { configure } from "../client/config.js";
import { refreshTokens, cleanupUserRefreshState } from "../client/refresh.js";
import { storeTokens } from "../client/storage.js";

// Lock-contention behavior of refreshTokens:
//  - A NON-FORCED (background/scheduled) refresh is best-effort: it try-locks
//    (timeout 0) instead of queueing, and when the holder doesn't finish in the
//    2s recovery wait it returns the still-valid cached token rather than
//    surfacing an error. A spurious lock timeout (e.g. timers firing before the
//    event loop resumes after laptop sleep) must never look like an auth
//    failure while the session is healthy.
//  - A FORCED refresh (post-401) needs a genuinely fresh token, so it still
//    queues on the lock and performs the network refresh once it acquires.

const createJWT = (claims: Record<string, unknown>) => {
  const enc = (obj: unknown) =>
    btoa(JSON.stringify(obj))
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/, "");
  return `${enc({ alg: "HS256", typ: "JWT" })}.${enc(claims)}.signature`;
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

const USERNAME = "testuser";
const LOCK_KEY = `Passwordless.testClient.${USERNAME}.refreshLock`;

const accessToken = (jti: string, expOffsetSec = 3600) =>
  createJWT({
    sub: "user123",
    username: USERNAME,
    jti,
    exp: Math.floor(Date.now() / 1000) + expOffsetSec,
    iat: Math.floor(Date.now() / 1000) + Math.min(0, expOffsetSec) - 3600,
  });

async function seedSession(jti = "cached", expOffsetSec = 3600) {
  const token = accessToken(jti, expOffsetSec);
  await storeTokens({
    accessToken: token,
    idToken: createJWT({
      sub: "user123",
      "cognito:username": USERNAME,
      exp: Math.floor(Date.now() / 1000) + expOffsetSec,
      iat: Math.floor(Date.now() / 1000),
    }),
    refreshToken: `refresh-${jti}`,
    authMethod: "SRP",
    expireAt: new Date(Date.now() + expOffsetSec * 1000),
  });
  return token;
}

const isRefreshApiCall = (init?: { headers?: Record<string, string> }) =>
  init?.headers?.["x-amz-target"]?.endsWith("GetTokensFromRefreshToken") ??
  false;

const refreshResponse = () => ({
  ok: true,
  status: 200,
  json: async () => ({
    AuthenticationResult: {
      AccessToken: accessToken("rotated"),
      IdToken: accessToken("rotated-id"),
      ExpiresIn: 3600,
      TokenType: "Bearer",
      RefreshToken: "refresh-rotated",
    },
  }),
});

describe("refreshTokens under lock contention", () => {
  afterEach(() => {
    cleanupUserRefreshState(USERNAME);
    jest.useRealTimers();
  });

  test("a non-forced refresh returns the still-valid cached token instead of erroring when the lock is held", async () => {
    const storage = createMemoryStorage();
    const fetchMock = jest.fn(
      async (_url: unknown, init?: { headers?: Record<string, string> }) => {
        if (isRefreshApiCall(init)) return refreshResponse();
        return { ok: true, status: 200, json: async () => ({}) };
      }
    );
    configure({
      clientId: "testClient",
      cognitoIdpEndpoint: "us-west-2",
      storage,
      useGetTokensFromRefreshToken: true,
      fetch: fetchMock as unknown as typeof fetch,
    });
    const cachedToken = await seedSession();

    // Another tab holds the refresh lock and keeps it fresh via heartbeat
    // renewal for the whole test — the holder never finishes.
    storage.setItem(
      LOCK_KEY,
      JSON.stringify({ id: "other-tab", timestamp: Date.now() })
    );
    const renewer = setInterval(() => {
      storage.setItem(
        LOCK_KEY,
        JSON.stringify({ id: "other-tab", timestamp: Date.now() })
      );
    }, 1000);

    try {
      const start = Date.now();
      const result = await refreshTokens();
      const durationMs = Date.now() - start;

      // Got the cached (still-valid) session back, not an error…
      expect(result.accessToken).toBe(cachedToken);
      expect(result.username).toBe(USERNAME);
      // …without queueing for the 45s acquisition timeout (try-immediate plus
      // the fixed 2s did-another-tab-finish wait).
      expect(durationMs).toBeLessThan(10_000);
      // And no network refresh happened in this tab.
      expect(
        fetchMock.mock.calls.some(([, init]) =>
          isRefreshApiCall(init as { headers?: Record<string, string> })
        )
      ).toBe(false);
      // The other tab's lock was never touched.
      expect(JSON.parse(storage.getItem(LOCK_KEY)!).id).toBe("other-tab");
    } finally {
      clearInterval(renewer);
    }
  }, 15000);

  test("a non-forced refresh with an EXPIRED access token queues for the lock instead of erroring after the 2s recovery", async () => {
    // The blocker case: an expired token has no cached-return fallback, so
    // best-effort try-lock would error into the caller (the React
    // incomplete-tokens effect treats that as terminal and signs the user
    // out). With no valid cached token, refreshTokens must queue for the
    // lock like it always used to, then perform the refresh.
    const storage = createMemoryStorage();
    const fetchMock = jest.fn(
      async (_url: unknown, init?: { headers?: Record<string, string> }) => {
        if (isRefreshApiCall(init)) return refreshResponse();
        return { ok: true, status: 200, json: async () => ({}) };
      }
    );
    configure({
      clientId: "testClient",
      cognitoIdpEndpoint: "us-west-2",
      storage,
      useGetTokensFromRefreshToken: true,
      fetch: fetchMock as unknown as typeof fetch,
    });
    // Access token expired an hour ago; refresh token still usable.
    await seedSession("expired", -3600);

    // Another tab holds the lock past the 2s recovery window, then releases.
    storage.setItem(
      LOCK_KEY,
      JSON.stringify({ id: "other-tab", timestamp: Date.now() })
    );
    setTimeout(() => storage.removeItem(LOCK_KEY), 3000);

    const result = await refreshTokens();

    // Queued past the release, then performed a REAL refresh.
    expect(result.accessToken).toBeTruthy();
    expect(result.accessToken).not.toContain('"jti":"expired"');
    expect(
      fetchMock.mock.calls.some(([, init]) =>
        isRefreshApiCall(init as { headers?: Record<string, string> })
      )
    ).toBe(true);
  }, 20000);

  test("a forced refresh queues for the lock and performs a real refresh once the holder releases", async () => {
    const storage = createMemoryStorage();
    const fetchMock = jest.fn(
      async (_url: unknown, init?: { headers?: Record<string, string> }) => {
        if (isRefreshApiCall(init)) return refreshResponse();
        return { ok: true, status: 200, json: async () => ({}) };
      }
    );
    configure({
      clientId: "testClient",
      cognitoIdpEndpoint: "us-west-2",
      storage,
      useGetTokensFromRefreshToken: true,
      fetch: fetchMock as unknown as typeof fetch,
    });
    const cachedToken = await seedSession();

    // Another tab holds the lock briefly, then releases it.
    storage.setItem(
      LOCK_KEY,
      JSON.stringify({ id: "other-tab", timestamp: Date.now() })
    );
    setTimeout(() => storage.removeItem(LOCK_KEY), 500);

    const result = await refreshTokens({ force: true });

    // The forced refresh waited for the release and got a FRESH token.
    expect(result.accessToken).not.toBe(cachedToken);
    expect(
      fetchMock.mock.calls.some(([, init]) =>
        isRefreshApiCall(init as { headers?: Record<string, string> })
      )
    ).toBe(true);
  }, 15000);
});
