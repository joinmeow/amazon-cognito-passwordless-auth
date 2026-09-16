import { configure } from "../client/config.js";
import { cleanupRefreshSystem, forceRefreshTokens } from "../client/refresh.js";
import {
  retrieveAuthMethod,
  retrieveTokensForRefresh,
  storeTokens,
} from "../client/storage.js";

const createJwt = (claims: Record<string, unknown>) => {
  const encode = (value: Record<string, unknown>) =>
    btoa(JSON.stringify(value))
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/, "");
  return `${encode({ alg: "none", typ: "JWT" })}.${encode(claims)}.signature`;
};

const createMemoryStorage = () => {
  const values = new Map<string, string>();
  return {
    getItem: async (key: string) => values.get(key) ?? null,
    setItem: async (key: string, value: string) => {
      values.set(key, value);
    },
    removeItem: async (key: string) => {
      values.delete(key);
    },
  };
};

afterEach(() => {
  cleanupRefreshSystem();
});

test("enterprise sessions round-trip and use Cognito refresh", async () => {
  const username = "enterprise-user";
  const now = Math.floor(Date.now() / 1000);
  const refreshedAccessToken = createJwt({
    sub: "user-subject",
    username,
    scope: "openid",
    iat: now,
    exp: now + 3600,
  });
  const refreshedIdToken = createJwt({
    sub: "user-subject",
    "cognito:username": username,
    iat: now,
    exp: now + 3600,
  });
  const requests: { input: string | URL; init?: RequestInit }[] = [];
  const fetchMock = jest.fn(async (input: string | URL, init?: RequestInit) => {
    requests.push({ input, init });
    return {
      ok: true,
      json: async () => ({
        AuthenticationResult: {
          AccessToken: refreshedAccessToken,
          IdToken: refreshedIdToken,
          ExpiresIn: 3600,
          TokenType: "Bearer",
        },
      }),
    };
  });
  const storage = createMemoryStorage();

  configure({
    clientId: "test-client",
    cognitoIdpEndpoint: "us-west-2",
    fetch: fetchMock as unknown as typeof fetch,
    storage,
    useGetTokensFromRefreshToken: true,
  });

  const tokens = {
    accessToken: createJwt({
      sub: "user-subject",
      username,
      scope: "openid",
      iat: now,
      exp: now + 60,
    }),
    idToken: createJwt({
      sub: "user-subject",
      "cognito:username": username,
      iat: now,
      exp: now + 60,
    }),
    refreshToken: "refresh-token",
    username,
    expireAt: new Date((now + 60) * 1000),
    authMethod: "ENTERPRISE" as const,
  };
  await storeTokens(tokens);

  expect(await retrieveAuthMethod(username)).toBe("ENTERPRISE");
  expect((await retrieveTokensForRefresh())?.authMethod).toBe("ENTERPRISE");

  const refreshed = await forceRefreshTokens({ tokens });

  expect(refreshed.authMethod).toBe("ENTERPRISE");
  expect(fetchMock).toHaveBeenCalledTimes(1);
  expect(requests[0].init?.headers?.["x-amz-target"]).toBe(
    "AWSCognitoIdentityProviderService.GetTokensFromRefreshToken"
  );
});
