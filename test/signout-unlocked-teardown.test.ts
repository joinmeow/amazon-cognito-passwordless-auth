import { configure } from "../client/config.js";
import { signOut } from "../client/common.js";
import { storeTokens } from "../client/storage.js";

// Phase 2 regression coverage: the LOCAL sign-out (tombstone, key removal,
// tokensRemovedLocallyCb, SIGNED_OUT status) must complete promptly WITHOUT
// waiting on the per-user refresh lock. A tab killed mid-refresh leaves an
// orphaned `.refreshLock` that stays fresh under an active heartbeat renewer;
// the old lock-wrapped teardown blocked /logout for the whole stale-takeover
// window. Revocation is bounded best-effort AFTER the local teardown.

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
const AMPLIFY_PREFIX = "CognitoIdentityServiceProvider.testClient";
const LOCK_KEY = `Passwordless.testClient.${USERNAME}.refreshLock`;
const TOMBSTONE_KEY = `Passwordless.testClient.${USERNAME}.signedOutAt`;

const isRevokeCall = (init?: { headers?: Record<string, string> }) =>
  init?.headers?.["x-amz-target"]?.endsWith("RevokeToken") ?? false;

const okResponse = () => ({ ok: true, status: 200, json: async () => ({}) });

async function seedSession(refreshToken = "original-refresh-token") {
  const now = Date.now();
  await storeTokens({
    accessToken: createJWT({
      sub: "user123",
      username: USERNAME,
      scope: "openid",
      exp: Math.floor((now + 3600_000) / 1000),
      iat: Math.floor(now / 1000),
    }),
    idToken: createJWT({
      sub: "user123",
      "cognito:username": USERNAME,
      exp: Math.floor((now + 3600_000) / 1000),
      iat: Math.floor(now / 1000),
    }),
    refreshToken,
    authMethod: "SRP",
    expireAt: new Date(now + 3600_000),
  });
}

describe("SignOut unlocked local teardown", () => {
  afterEach(() => {
    jest.useRealTimers();
  });

  test("tears the session down promptly while another owner holds and heartbeat-renews the refresh lock", async () => {
    const storage = createMemoryStorage();
    const fetchMock = jest.fn().mockResolvedValue(okResponse());
    configure({
      clientId: "testClient",
      cognitoIdpEndpoint: "us-west-2",
      storage,
      fetch: fetchMock as unknown as typeof fetch,
    });
    await seedSession();

    // Another tab holds the refresh lock and keeps renewing it, so it never
    // goes stale. The old teardown would block here until the 45s acquisition
    // timeout, then fall back to the unlocked path (~45s of spinner).
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
      const callback = jest.fn();
      const statuses: string[] = [];
      const start = Date.now();
      const { signedOut } = signOut({
        tokensRemovedLocallyCb: callback,
        statusCb: (s) => statuses.push(s),
      });
      await signedOut;
      const durationMs = Date.now() - start;

      // The whole point of Phase 2: no stale-takeover / lock-timeout wait.
      expect(durationMs).toBeLessThan(3000);
      expect(callback).toHaveBeenCalledTimes(1);
      expect(statuses).toContain("SIGNED_OUT");

      // Local session is gone and the tombstone was planted.
      expect(storage.getItem(`${AMPLIFY_PREFIX}.LastAuthUser`)).toBeNull();
      expect(
        storage.getItem(`${AMPLIFY_PREFIX}.${USERNAME}.refreshToken`)
      ).toBeNull();
      expect(storage.getItem(TOMBSTONE_KEY)).toBeTruthy();

      // Sign-out never touched the other tab's lock.
      expect(JSON.parse(storage.getItem(LOCK_KEY)!).id).toBe("other-tab");
    } finally {
      clearInterval(renewer);
    }
  }, 15000);

  test("fires tokensRemovedLocallyCb (the navigation signal) before server revocation resolves", async () => {
    const storage = createMemoryStorage();
    let releaseRevoke!: () => void;
    const revokeGate = new Promise<void>((resolve) => {
      releaseRevoke = resolve;
    });
    const fetchMock = jest.fn(
      (_url: unknown, init?: { headers?: Record<string, string> }) =>
        isRevokeCall(init)
          ? revokeGate.then(() => okResponse())
          : Promise.resolve(okResponse())
    );
    configure({
      clientId: "testClient",
      cognitoIdpEndpoint: "us-west-2",
      storage,
      fetch: fetchMock as unknown as typeof fetch,
    });
    await seedSession();

    // Resolve off the callback itself rather than a fixed sleep: the assertion
    // is about ordering, so waiting a wall-clock guess would flake under load.
    let markCallbackFired!: () => void;
    const callbackFired = new Promise<void>((resolve) => {
      markCallbackFired = resolve;
    });
    const callback = jest.fn(() => markCallbackFired());
    let resolved = false;
    const { signedOut } = signOut({ tokensRemovedLocallyCb: callback });
    void signedOut.then(() => {
      resolved = true;
    });

    await callbackFired;

    // Local removal + navigation callback have already happened...
    expect(callback).toHaveBeenCalledTimes(1);
    expect(storage.getItem(`${AMPLIFY_PREFIX}.LastAuthUser`)).toBeNull();
    // ...but signedOut is still pending on the outstanding revocation.
    expect(resolved).toBe(false);

    releaseRevoke();
    await signedOut;
    expect(resolved).toBe(true);
    expect(
      fetchMock.mock.calls.some(([, init]) =>
        isRevokeCall(init as { headers?: Record<string, string> })
      )
    ).toBe(true);
  });

  test("bounds a hung revocation so signedOut cannot hang forever, and stays signed out", async () => {
    jest.useFakeTimers();
    const storage = createMemoryStorage();
    // RevokeToken never responds on its own; it only settles when its signal
    // aborts (mirrors a black-holed connection).
    const fetchMock = jest.fn(
      (
        _url: unknown,
        init?: { headers?: Record<string, string>; signal?: AbortSignal }
      ) => {
        if (isRevokeCall(init)) {
          return new Promise((_resolve, reject) => {
            init?.signal?.addEventListener("abort", () =>
              reject(new DOMException("Aborted", "AbortError"))
            );
          });
        }
        return Promise.resolve(okResponse());
      }
    );
    configure({
      clientId: "testClient",
      cognitoIdpEndpoint: "us-west-2",
      storage,
      fetch: fetchMock as unknown as typeof fetch,
    });
    await seedSession();

    const callback = jest.fn();
    let resolved = false;
    const { signedOut } = signOut({ tokensRemovedLocallyCb: callback });
    void signedOut.then(() => {
      resolved = true;
    });

    // Local teardown completes without advancing the clock.
    await jest.advanceTimersByTimeAsync(1);
    expect(callback).toHaveBeenCalledTimes(1);
    expect(storage.getItem(`${AMPLIFY_PREFIX}.LastAuthUser`)).toBeNull();
    expect(resolved).toBe(false);

    // The 5s revoke deadline aborts the hung call; signedOut then resolves.
    await jest.advanceTimersByTimeAsync(5100);
    expect(resolved).toBe(true);

    // A failed revocation must never resurrect the local session.
    expect(storage.getItem(`${AMPLIFY_PREFIX}.LastAuthUser`)).toBeNull();
    expect(
      storage.getItem(`${AMPLIFY_PREFIX}.${USERNAME}.refreshToken`)
    ).toBeNull();
    expect(storage.getItem(TOMBSTONE_KEY)).toBeTruthy();
  });

  test("a second sign-out after the session is gone is an immediate no-op that still fires its callback once", async () => {
    const storage = createMemoryStorage();
    const fetchMock = jest.fn().mockResolvedValue(okResponse());
    configure({
      clientId: "testClient",
      cognitoIdpEndpoint: "us-west-2",
      storage,
      fetch: fetchMock as unknown as typeof fetch,
    });
    await seedSession();

    await signOut({ skipTokenRevocation: true }).signedOut;
    expect(storage.getItem(`${AMPLIFY_PREFIX}.LastAuthUser`)).toBeNull();

    const secondCallback = jest.fn();
    const start = Date.now();
    await signOut({ tokensRemovedLocallyCb: secondCallback }).signedOut;

    expect(Date.now() - start).toBeLessThan(1000);
    expect(secondCallback).toHaveBeenCalledTimes(1);
  }, 10000);
});
