/**
 * Tests for the debug-log redaction helpers: token material (access/ID/refresh
 * tokens, SRP secret blocks, device keys, client secrets) must never appear in
 * full in debug output, while logs stay diagnostically useful (short prefix +
 * length are preserved).
 */
// jsdom doesn't define TextDecoder/TextEncoder, which parseJwtPayload (used
// internally by storeTokens) relies on. Provide Node's.
import { TextEncoder, TextDecoder } from "util";
Object.assign(globalThis, {
  TextEncoder: globalThis.TextEncoder ?? TextEncoder,
  TextDecoder: globalThis.TextDecoder ?? TextDecoder,
});

import { redactSecret, redactTokensFromObject } from "../client/util.js";
import { configure } from "../client/config.js";
import { storeTokens } from "../client/storage.js";
import { handleAuthResponse } from "../client/cognito-api.js";

// Minimal unsigned JWT builder (matches the helper used in the other tests)
const createJWT = (claims: Record<string, unknown>) => {
  const enc = (obj: unknown) =>
    btoa(JSON.stringify(obj))
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/, "");
  return `${enc({ alg: "HS256", typ: "JWT" })}.${enc(claims)}.signature`;
};

describe("redactSecret", () => {
  test("keeps a short prefix and the length, never the full value", () => {
    expect(redactSecret("abcdefghij")).toBe("abcde…[redacted, 10 chars]");
  });

  test("supports a custom number of visible chars", () => {
    expect(redactSecret("abcdefghij", 2)).toBe("ab…[redacted, 10 chars]");
  });

  test("emits no prefix at all for values shorter than the visible prefix", () => {
    expect(redactSecret("abc")).toBe("[redacted, 3 chars]");
    expect(redactSecret("")).toBe("[redacted, 0 chars]");
  });
});

describe("redactTokensFromObject", () => {
  test("redacts tokens nested in a Cognito AuthenticationResult", () => {
    const accessToken = "eyAccessToken.AAAA.BBBB";
    const refreshToken = "eyRefreshToken-CCCC-DDDD";
    const response = {
      AuthenticationResult: {
        AccessToken: accessToken,
        IdToken: "eyIdToken.EEEE.FFFF",
        RefreshToken: refreshToken,
        ExpiresIn: 3600,
        TokenType: "Bearer",
        NewDeviceMetadata: {
          DeviceKey: "us-west-2_11111111-2222-3333-4444-555555555555",
          DeviceGroupKey: "-group",
        },
      },
    };
    const redacted = redactTokensFromObject(response);
    const serialized = JSON.stringify(redacted);
    expect(serialized).not.toContain(accessToken);
    expect(serialized).not.toContain(refreshToken);
    expect(serialized).not.toContain("eyIdToken.EEEE.FFFF");
    expect(serialized).not.toContain(
      "us-west-2_11111111-2222-3333-4444-555555555555"
    );
    // Non-sensitive diagnostics are preserved
    const result = (
      redacted as { AuthenticationResult: Record<string, unknown> }
    ).AuthenticationResult;
    expect(result.ExpiresIn).toBe(3600);
    expect(result.TokenType).toBe("Bearer");
    expect(result.AccessToken).toBe(
      `eyAcc…[redacted, ${accessToken.length} chars]`
    );
  });

  test("redacts the SRP SECRET_BLOCK in challenge parameters but keeps public values", () => {
    const challenge = {
      ChallengeName: "PASSWORD_VERIFIER",
      ChallengeParameters: {
        SECRET_BLOCK: "c2VjcmV0LWJsb2NrLWNvbnRlbnQ=",
        SRP_B: "abcdef123456",
        SALT: "deadbeef",
        USER_ID_FOR_SRP: "user-1",
      },
    };
    const redacted = redactTokensFromObject(challenge) as typeof challenge;
    expect(JSON.stringify(redacted)).not.toContain(
      "c2VjcmV0LWJsb2NrLWNvbnRlbnQ="
    );
    expect(redacted.ChallengeParameters.SRP_B).toBe("abcdef123456");
    expect(redacted.ChallengeParameters.SALT).toBe("deadbeef");
    expect(redacted.ChallengeParameters.USER_ID_FOR_SRP).toBe("user-1");
  });

  test("matches sensitive keys case-insensitively and with underscores (OAuth style)", () => {
    const hashParams = {
      access_token: "oauth-access-token-value",
      id_token: "oauth-id-token-value",
      refresh_token: "oauth-refresh-token-value",
      expires_in: "3600",
      token_type: "Bearer",
    };
    const redacted = redactTokensFromObject(hashParams) as typeof hashParams;
    expect(JSON.stringify(redacted)).not.toContain("oauth-access-token-value");
    expect(JSON.stringify(redacted)).not.toContain("oauth-refresh-token-value");
    expect(redacted.expires_in).toBe("3600");
    expect(redacted.token_type).toBe("Bearer");
  });

  test("passes non-object and non-string values through unchanged", () => {
    expect(redactTokensFromObject("just a string")).toBe("just a string");
    expect(redactTokensFromObject(42)).toBe(42);
    expect(redactTokensFromObject(null)).toBeNull();
    expect(redactTokensFromObject(undefined)).toBeUndefined();
    // A sensitive key with a non-string value is left as-is
    const redacted = redactTokensFromObject({ AccessToken: 42 }) as {
      AccessToken: number;
    };
    expect(redacted.AccessToken).toBe(42);
  });

  test("leaves class instances alone and does not mutate the input", () => {
    const expireAt = new Date();
    const tokens = {
      accessToken: "the-access-token-value",
      refreshToken: "the-refresh-token-value",
      expireAt,
      username: "testuser",
    };
    const redacted = redactTokensFromObject(tokens) as typeof tokens;
    expect(redacted.expireAt).toBe(expireAt);
    expect(redacted.username).toBe("testuser");
    expect(redacted.accessToken).not.toBe("the-access-token-value");
    // Original untouched
    expect(tokens.accessToken).toBe("the-access-token-value");
    expect(tokens.refreshToken).toBe("the-refresh-token-value");
  });
});

describe("debug call sites do not leak token material", () => {
  beforeEach(() => {
    localStorage.clear();
  });

  test("storeTokens debug output never contains the full tokens", async () => {
    const debug = jest.fn();
    configure({
      clientId: "testClient",
      cognitoIdpEndpoint: "us-west-2",
      fetch: jest.fn(),
      debug,
    });

    const accessToken = createJWT({
      sub: "sub-1",
      username: "testuser",
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + 3600,
    });
    const refreshToken =
      "eyJjdHkiOiJKV1QiLCJlbmMiOiJBMjU2R0NNIn0.this-is-a-very-secret-refresh-token";
    const deviceKey = "us-west-2_11111111-2222-3333-4444-555555555555";

    await storeTokens({
      accessToken,
      refreshToken,
      deviceKey,
      username: "testuser",
      expireAt: new Date(Date.now() + 3600_000),
    });

    expect(debug).toHaveBeenCalled();
    const allDebugOutput = JSON.stringify(debug.mock.calls);
    expect(allDebugOutput).not.toContain(accessToken);
    expect(allDebugOutput).not.toContain(refreshToken);
    expect(allDebugOutput).not.toContain(deviceKey);
  });

  test("DEVICE_PASSWORD_VERIFIER challenge parameters are redacted in debug output", async () => {
    const debug = jest.fn();
    const secretBlock = "ZGV2aWNlLXNycC1zZWNyZXQtYmxvY2stY29udGVudA==";
    const deviceKey = "us-west-2_66666666-7777-8888-9999-000000000000";
    const accessToken = "eyAccessToken.GGGG.HHHH";
    const refreshToken = "eyRefreshToken-KKKK-LLLL";
    // Pretend the Cognito advanced security script is already loaded, so
    // respondToAuthChallenge doesn't try to inject a <script> in jsdom
    (
      window as { AmazonCognitoAdvancedSecurityData?: unknown }
    ).AmazonCognitoAdvancedSecurityData = { getData: () => undefined };
    configure({
      clientId: "testClient",
      cognitoIdpEndpoint: "us-west-2",
      fetch: jest.fn().mockResolvedValue({
        ok: true,
        json: () =>
          Promise.resolve({
            AuthenticationResult: {
              AccessToken: accessToken,
              IdToken: "eyIdToken.MMMM.NNNN",
              RefreshToken: refreshToken,
              ExpiresIn: 3600,
              TokenType: "Bearer",
            },
            ChallengeParameters: {},
          }),
      }),
      debug,
    });

    const result = await handleAuthResponse({
      authResponse: {
        ChallengeName: "DEVICE_PASSWORD_VERIFIER",
        ChallengeParameters: {
          SRP_B: "abcdef123456",
          SECRET_BLOCK: secretBlock,
          DEVICE_KEY: deviceKey,
          SALT: "deadbeef",
          USERNAME: "testuser",
        },
        Session: "session-1",
      },
      username: "testuser",
      deviceHandler: {
        deviceKey,
        generateStep1: () => Promise.resolve({ srpAHex: "aa" }),
        generateStep2: () =>
          Promise.resolve({
            passwordVerifier: "password-claim-signature",
            passwordClaimSecretBlock: secretBlock,
            timestamp: "Mon Jun 9 00:00:00 UTC 2026",
          }),
      },
    });

    // The flow itself still works on the unredacted values
    expect(result.accessToken).toBe(accessToken);

    expect(debug).toHaveBeenCalledWith(
      "DEVICE_PASSWORD_VERIFIER parameters:",
      expect.anything()
    );
    const allDebugOutput = JSON.stringify(debug.mock.calls);
    expect(allDebugOutput).not.toContain(secretBlock);
    expect(allDebugOutput).not.toContain(deviceKey);
    expect(allDebugOutput).not.toContain(accessToken);
    expect(allDebugOutput).not.toContain(refreshToken);
    // Public SRP values stay visible for diagnostics
    expect(allDebugOutput).toContain("abcdef123456");
  });
});
