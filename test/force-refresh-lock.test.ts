import { configure } from "../client/config.js";
import {
  forceRefreshTokens,
  cleanupUserRefreshState,
} from "../client/refresh.js";
import { storeTokens } from "../client/storage.js";

const createJWT = (claims: Record<string, unknown>) => {
  const enc = (o: unknown) =>
    btoa(JSON.stringify(o))
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/, "");
  return `${enc({ alg: "HS256", typ: "JWT" })}.${enc(claims)}.sig`;
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
    _store: store,
  };
}

const seed = async (username: string, refreshToken: string) => {
  const now = Date.now();
  await storeTokens({
    accessToken: createJWT({
      sub: "u",
      username,
      exp: Math.floor((now + 3600_000) / 1000),
      iat: Math.floor(now / 1000),
    }),
    idToken: createJWT({
      sub: "u",
      "cognito:username": username,
      exp: Math.floor((now + 3600_000) / 1000),
      iat: Math.floor(now / 1000),
    }),
    refreshToken,
    authMethod: "SRP",
    expireAt: new Date(now + 3600_000),
  });
};

const refreshOk = (username: string, newRefresh: string) => {
  const now = Date.now();
  return {
    ok: true,
    status: 200,
    json: async () => ({
      AuthenticationResult: {
        AccessToken: createJWT({
          sub: "u",
          username,
          exp: Math.floor((now + 7200_000) / 1000),
          iat: Math.floor(now / 1000),
        }),
        IdToken: createJWT({
          sub: "u",
          "cognito:username": username,
          exp: Math.floor((now + 7200_000) / 1000),
          iat: Math.floor(now / 1000),
        }),
        RefreshToken: newRefresh,
        ExpiresIn: 3600,
        TokenType: "Bearer",
      },
    }),
  };
};

afterEach(() => {
  jest.useRealTimers();
  cleanupUserRefreshState("testuser");
});

describe("forceRefreshTokens goes through the per-user lock", () => {
  test("waits for a held lock rather than bypassing it", async () => {
    jest.useFakeTimers();
    const username = "testuser";
    const storage = createMemoryStorage();
    const fetchMock = jest.fn((url: unknown, init?: { headers?: Record<string, string> }) => {
      const target = init?.headers?.["x-amz-target"] ?? "";
      if (
        target.endsWith("GetTokensFromRefreshToken") ||
        target.endsWith("InitiateAuth")
      ) {
        return Promise.resolve(refreshOk(username, "rotated-by-force"));
      }
      return Promise.resolve({ ok: true, status: 200, json: async () => ({}) });
    });
    configure({
      clientId: "testClient",
      cognitoIdpEndpoint: "us-west-2",
      storage,
      fetch: fetchMock as unknown as typeof fetch,
    });
    await seed(username, "original-refresh");

    // Another tab holds the refresh lock and keeps renewing it for a while
    const lockKey = `Passwordless.testClient.${username}.refreshLock`;
    storage.setItem(
      lockKey,
      JSON.stringify({ id: "other-tab", timestamp: Date.now() })
    );
    let renews = 6;
    const renewer = setInterval(() => {
      if (renews-- > 0) {
        storage.setItem(
          lockKey,
          JSON.stringify({ id: "other-tab", timestamp: Date.now() })
        );
      }
    }, 5_000);

    try {
      const outcome: { done: boolean; value?: unknown; error?: unknown } = {
        done: false,
      };
      forceRefreshTokens().then(
        (v) => {
          outcome.done = true;
          outcome.value = v;
        },
        (e) => {
          outcome.done = true;
          outcome.error = e;
        }
      );

      // While the foreign lock is held & renewed, the force refresh must NOT
      // have hit the token endpoint yet (it's waiting for the lock, not
      // bypassing it)
      await jest.advanceTimersByTimeAsync(8_000);
      expect(
        fetchMock.mock.calls.some(([, init]) =>
          (init as { headers?: Record<string, string> })?.headers?.[
            "x-amz-target"
          ]?.endsWith("GetTokensFromRefreshToken")
        )
      ).toBe(false);
      expect(outcome.done).toBe(false);

      // Once the other tab stops renewing, the lock goes stale and the force
      // refresh takes it over and completes
      clearInterval(renewer);
      for (let i = 0; i < 90 && !outcome.done; i++) {
        await jest.advanceTimersByTimeAsync(1000);
      }
      expect(outcome.done).toBe(true);
      expect(outcome.error).toBeUndefined();
      expect(
        (outcome.value as { refreshToken?: string }).refreshToken
      ).toBe("rotated-by-force");
    } finally {
      clearInterval(renewer);
    }
  });
});
