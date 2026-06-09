import { configure } from "../client/config.js";
import { signOut } from "../client/common.js";
import { storeTokens } from "../client/storage.js";

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

const createTokens = (username: string, expiresInMs: number) => {
  const now = Date.now();
  return {
    accessToken: createJWT({
      sub: username,
      username,
      exp: Math.floor((now + expiresInMs) / 1000),
      iat: Math.floor(now / 1000),
    }),
    refreshToken: `${username}-refresh-token`,
    username,
    expireAt: new Date(now + expiresInMs),
  };
};

describe("Sign-out keeps global refresh listeners", () => {
  let debugLogs: string[] = [];

  beforeEach(() => {
    debugLogs = [];
    configure({
      clientId: "testClient",
      cognitoIdpEndpoint: "us-west-2",
      debug: (...args: unknown[]) => {
        debugLogs.push(args.map(String).join(" "));
      },
    });
  });

  test("signOut cleans up the user's refresh state without removing global listeners", async () => {
    await storeTokens(createTokens("userA", 3600000));

    const docRemoveSpy = jest.spyOn(document, "removeEventListener");
    const globalRemoveSpy = jest.spyOn(globalThis, "removeEventListener");

    const { signedOut } = signOut({ skipTokenRevocation: true });
    await signedOut;

    // Per-user cleanup ran ...
    expect(
      debugLogs.some((log) => log.includes("Cleaning up user refresh state"))
    ).toBe(true);
    // ... but the global teardown did NOT run
    expect(
      debugLogs.some((log) => log.includes("Cleaning up refresh system"))
    ).toBe(false);

    // The global visibilitychange listener must still be registered
    const removedDocEvents = docRemoveSpy.mock.calls.map((call) => call[0]);
    expect(removedDocEvents).not.toContain("visibilitychange");

    // The watchdog's unload auto-cleanup listeners must still be registered
    const removedGlobalEvents = globalRemoveSpy.mock.calls.map(
      (call) => call[0]
    );
    expect(removedGlobalEvents).not.toContain("beforeunload");
    expect(removedGlobalEvents).not.toContain("pagehide");
    expect(removedGlobalEvents).not.toContain("unload");

    docRemoveSpy.mockRestore();
    globalRemoveSpy.mockRestore();
  });

  test("visibilitychange recovery still works for user B after user A signs out", async () => {
    // User A signs out
    await storeTokens(createTokens("userA", 3600000));
    const { signedOut } = signOut({ skipTokenRevocation: true });
    await signedOut;

    // User B signs in
    await storeTokens(createTokens("userB", 3600000));

    // Simulate wake-from-sleep / tab becoming visible again
    debugLogs = [];
    document.dispatchEvent(new Event("visibilitychange"));
    // The handler is async, give it a moment to run
    await new Promise((resolve) => setTimeout(resolve, 50));

    // The global visibilitychange handler must still fire for user B
    expect(
      debugLogs.some((log) => log.includes("visibilitychange event:"))
    ).toBe(true);
  });
});
