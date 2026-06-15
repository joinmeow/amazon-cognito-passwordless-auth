// Per-test module isolation: processTokens launches fire-and-forget
// scheduleRefresh chains that can outlive the test that started them; a
// fresh module graph per test keeps stragglers bound to the previous test's
// storage so they can't touch the running one (see refresh-bugs.test.ts).
let configure: typeof import("../client/config.js").configure;
let processTokens: typeof import("../client/common.js").processTokens;
let signOut: typeof import("../client/common.js").signOut;
let cleanupUserRefreshState: typeof import("../client/refresh.js").cleanupUserRefreshState;

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
  };
}

const USERNAME = "testuser";
let debugLogs: string[];

// processTokens takes the auth lock (jittered sleeps) under fake timers, so
// awaiting it directly would hang. Advance fake time in small steps until
// the promise settles.
async function settle<T>(p: Promise<T>): Promise<T> {
  let done = false;
  const wrapped = p.finally(() => {
    done = true;
  });
  for (let i = 0; i < 100 && !done; i++) {
    await jest.advanceTimersByTimeAsync(50);
  }
  return wrapped;
}

const baseTokens = () => {
  const now = Date.now();
  return {
    accessToken: createJWT({
      sub: "u",
      username: USERNAME,
      exp: Math.floor((now + 3600_000) / 1000),
      iat: Math.floor(now / 1000),
    }),
    idToken: createJWT({
      sub: "u",
      "cognito:username": USERNAME,
      exp: Math.floor((now + 3600_000) / 1000),
      iat: Math.floor(now / 1000),
    }),
    refreshToken: "refresh-token",
    expireAt: new Date(now + 3600_000),
    username: USERNAME,
    authMethod: "SRP" as const,
  };
};

beforeEach(async () => {
  jest.resetModules();
  jest.useFakeTimers();
  ({ configure } = await import("../client/config.js"));
  ({ processTokens, signOut } = await import("../client/common.js"));
  ({ cleanupUserRefreshState } = await import("../client/refresh.js"));

  debugLogs = [];
  configure({
    clientId: "testClient",
    cognitoIdpEndpoint: "us-west-2",
    // Refreshes never actually fire in these tests (we assert on the
    // scheduling debug logs, not on refresh results); a rejecting fetch
    // keeps any stray scheduled refresh from doing real work.
    fetch: jest.fn(() =>
      Promise.reject(new Error("no network in test"))
    ) as unknown as typeof fetch,
    storage: createMemoryStorage(),
    debug: (...args: unknown[]) => debugLogs.push(args.map(String).join(" ")),
  });
});

afterEach(async () => {
  cleanupUserRefreshState(USERNAME);
  await jest.advanceTimersByTimeAsync(0);
  jest.useRealTimers();
});

describe("processTokens fresh-login deferral", () => {
  test("schedules immediately when newDeviceMetadata is present but undefined (FIDO2/OAuth)", async () => {
    // The FIDO2 / hosted-OAuth token objects set newDeviceMetadata to
    // undefined; the old `"key" in obj` check treated that as a fresh login
    // and deferred scheduling for every such flow.
    await settle(
      processTokens({ ...baseTokens(), newDeviceMetadata: undefined })
    );

    expect(debugLogs.some((l) => l.includes("Fresh login detected"))).toBe(
      false
    );
    expect(
      debugLogs.some((l) => l.includes("Scheduling token refresh"))
    ).toBe(true);
  });

  test("defers scheduling only for a genuine fresh login with a new device key", async () => {
    await settle(
      processTokens({
        ...baseTokens(),
        newDeviceMetadata: {
          deviceKey: "us-west-2_dev",
          deviceGroupKey: "grp",
        },
      })
    );

    // Deferred: not scheduled yet
    expect(debugLogs.some((l) => l.includes("Fresh login detected"))).toBe(
      true
    );
    expect(
      debugLogs.some((l) => l.includes("Scheduling token refresh"))
    ).toBe(false);

    // Fires after the 2-minute deferral
    debugLogs.length = 0;
    await jest.advanceTimersByTimeAsync(120_000);
    expect(
      debugLogs.some((l) => l.includes("Scheduling token refresh"))
    ).toBe(true);
  });

  test("cancels a pending fresh-login deferral on sign-out", async () => {
    await settle(
      processTokens({
        ...baseTokens(),
        newDeviceMetadata: {
          deviceKey: "us-west-2_dev",
          deviceGroupKey: "grp",
        },
      })
    );
    expect(debugLogs.some((l) => l.includes("Fresh login detected"))).toBe(
      true
    );

    // Sign out before the 2-minute deferral fires
    await settle(signOut().signedOut);

    // Advance past the deferral window: the cancelled timer must NOT schedule
    debugLogs.length = 0;
    await jest.advanceTimersByTimeAsync(180_000);
    expect(
      debugLogs.some((l) => l.includes("Scheduling token refresh"))
    ).toBe(false);
  });
});
