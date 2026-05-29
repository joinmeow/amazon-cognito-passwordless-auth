/**
 * Regression tests for client clock-skew tolerance.
 *
 * Before this fix, token validity was `serverExp <= Date.now()` with no skew
 * correction, so a device whose clock was hours fast saw every freshly-issued
 * token as already-expired: `retrieveTokens()` dropped the session and the app
 * bounced signin -> / -> logout -> signin without ever calling the API.
 *
 * The fix captures the client clock drift at token receipt (local time minus
 * the access token's `iat`) and evaluates expiry against a corrected clock.
 * Crucially the drift is anchored at receipt, so a genuinely-expired/aged token
 * is still treated as expired.
 */
// jsdom doesn't define TextDecoder/TextEncoder, which the real parseJwtPayload
// (used internally by computeClockDriftMs) relies on. Provide Node's.
import { TextEncoder, TextDecoder } from "util";
Object.assign(globalThis, {
  TextEncoder: globalThis.TextEncoder ?? TextEncoder,
  TextDecoder: globalThis.TextDecoder ?? TextDecoder,
});

import { configure } from "../client/config.js";
import { storeTokens, retrieveTokens } from "../client/storage.js";
import { signOut } from "../client/common.js";
import { computeClockDriftMs } from "../client/util.js";

const HOUR = 3600_000;

// Minimal unsigned JWT builder (matches the helper used in the other tests)
const createJWT = (claims: Record<string, unknown>) => {
  const enc = (obj: unknown) =>
    btoa(JSON.stringify(obj))
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/, "");
  return `${enc({ alg: "HS256", typ: "JWT" })}.${enc(claims)}.sig`;
};

describe("client clock-skew tolerance", () => {
  beforeEach(() => {
    localStorage.clear();
    configure({
      clientId: "testClient",
      cognitoIdpEndpoint: "us-west-2",
      fetch: jest.fn(),
    });
  });

  describe("computeClockDriftMs", () => {
    test("reports a positive drift (~3h) when the device clock is ahead", () => {
      const now = Date.now();
      // iat is 3h in the past relative to the (correct) test clock => the
      // device that issued this "now" reading is ~3h ahead of the server.
      const token = createJWT({ iat: Math.floor((now - 3 * HOUR) / 1000) });
      const drift = computeClockDriftMs(token);
      expect(drift).toBeGreaterThan(3 * HOUR - 60_000);
      expect(drift).toBeLessThan(3 * HOUR + 60_000);
    });

    test("returns 0 for a freshly issued token (no skew)", () => {
      const token = createJWT({ iat: Math.floor(Date.now() / 1000) });
      expect(Math.abs(computeClockDriftMs(token))).toBeLessThan(60_000);
    });

    test("returns 0 for missing / unparseable tokens (preserves old behavior)", () => {
      expect(computeClockDriftMs(undefined)).toBe(0);
      expect(computeClockDriftMs("not-a-jwt")).toBe(0);
      expect(computeClockDriftMs(createJWT({ sub: "u" }))).toBe(0); // no iat
    });
  });

  describe("retrieveTokens expiry evaluation", () => {
    test("FAST CLOCK: a token that looks expired locally but is valid in server time is retained", async () => {
      const now = Date.now();
      const driftMs = 3 * HOUR; // device clock 3h fast, captured at receipt
      await storeTokens({
        accessToken: createJWT({
          sub: "u",
          username: "fastuser",
          // server time: issued ~now-drift; expires 2h ago in *client* time
          iat: Math.floor((now - driftMs) / 1000),
          exp: Math.floor((now - 2 * HOUR) / 1000),
        }),
        refreshToken: "r",
        username: "fastuser",
        expireAt: new Date(now - 2 * HOUR),
        clockDriftMs: driftMs,
      });

      const retrieved = await retrieveTokens();
      // Without the fix this is undefined (token dropped). With it, the session survives.
      expect(retrieved).toBeDefined();
      expect(retrieved?.username).toBe("fastuser");
      expect(retrieved?.clockDriftMs).toBe(driftMs);
    });

    test("GENUINELY EXPIRED (no drift): token is still dropped", async () => {
      const now = Date.now();
      await storeTokens({
        accessToken: createJWT({
          sub: "u",
          username: "expireduser",
          iat: Math.floor((now - 2 * HOUR) / 1000),
          exp: Math.floor((now - 1 * HOUR) / 1000),
        }),
        refreshToken: "r",
        username: "expireduser",
        expireAt: new Date(now - 1 * HOUR),
        // no clockDriftMs => correction defaults to 0 => previous behavior
      });

      expect(await retrieveTokens()).toBeUndefined();
    });

    test("FAST CLOCK but token truly past its lifetime: still dropped (no false validity)", async () => {
      const now = Date.now();
      const driftMs = 3 * HOUR;
      await storeTokens({
        accessToken: createJWT({
          sub: "u",
          username: "staleuser",
          iat: Math.floor((now - driftMs - 1 * HOUR) / 1000),
          // expired ~1h ago even after correcting for the 3h drift
          exp: Math.floor((now - 4 * HOUR) / 1000),
        }),
        refreshToken: "r",
        username: "staleuser",
        expireAt: new Date(now - 4 * HOUR),
        clockDriftMs: driftMs,
      });

      expect(await retrieveTokens()).toBeUndefined();
    });

    test("CORRECT CLOCK: a normal valid token is retained with ~0 drift", async () => {
      const now = Date.now();
      await storeTokens({
        accessToken: createJWT({
          sub: "u",
          username: "okuser",
          iat: Math.floor(now / 1000),
          exp: Math.floor((now + 1 * HOUR) / 1000),
        }),
        refreshToken: "r",
        username: "okuser",
        expireAt: new Date(now + 1 * HOUR),
        clockDriftMs: 0,
      });

      const retrieved = await retrieveTokens();
      expect(retrieved).toBeDefined();
      expect(retrieved?.clockDriftMs).toBe(0);
    });
  });

  describe("sign-out cleanup", () => {
    test("removes the persisted clockDriftMs key on sign-out", async () => {
      const now = Date.now();
      await storeTokens({
        accessToken: createJWT({
          sub: "u",
          username: "souser",
          iat: Math.floor(now / 1000),
          exp: Math.floor((now + HOUR) / 1000),
        }),
        refreshToken: "r",
        username: "souser",
        expireAt: new Date(now + HOUR),
        clockDriftMs: 2 * HOUR,
      });

      const { storage } = configure();
      const driftKey =
        "CognitoIdentityServiceProvider.testClient.souser.clockDriftMs";
      expect(await storage.getItem(driftKey)).not.toBeNull();

      const { signedOut } = signOut({ skipTokenRevocation: true });
      await signedOut;

      expect(await storage.getItem(driftKey)).toBeNull();
    });
  });
});
