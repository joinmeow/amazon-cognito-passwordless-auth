import { configure } from "../client/config.js";
import { refreshTokens } from "../client/refresh.js";
import type { MinimalResponse } from "../client/config.js";

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

const base64UrlEncode = (str: string) =>
  btoa(str).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

// Create a simple JWT token for testing
const createMockJWT = (payload: Record<string, unknown>) => {
  const header = base64UrlEncode(JSON.stringify({ alg: "HS256", typ: "JWT" }));
  const body = base64UrlEncode(JSON.stringify(payload));
  return `${header}.${body}.signature`;
};

describe("RefreshTokens Lock", () => {
  test("should serialize concurrent refresh calls", async () => {
    // Configure test environment with fetch stub
    let callCount = 0;
    const callOrder: number[] = [];
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    const dummyFetch = async (_input: string | URL, _init?: { 
      signal?: AbortSignal; 
      headers?: Record<string, string>; 
      method?: string; 
      body?: string; 
    }) => {
      callCount++;
      callOrder.push(callCount);
      await sleep(100);

      const accessToken = createMockJWT({
        sub: "user123",
        username: "testuser",
        exp: Math.floor(Date.now() / 1000) + 3600, // 1 hour from now
        iat: Math.floor(Date.now() / 1000),
      });

      const response: MinimalResponse = {
        ok: true,
        json: async () => ({
          access_token: accessToken,
          id_token: createMockJWT({
            sub: "user123",
            "cognito:username": "testuser",
            email: "test@example.com",
            exp: Math.floor(Date.now() / 1000) + 3600,
            iat: Math.floor(Date.now() / 1000),
          }),
          refresh_token: `refresh-${callCount}`,
          expires_in: 3600,
          token_type: "Bearer",
        }),
      };
      return response;
    };

    configure({
      clientId: "testClient",
      cognitoIdpEndpoint: "us-west-2",
      fetch: dummyFetch,
      useGetTokensFromRefreshToken: false, // force OAuth path
    });

    // Define dummy tokens payload with proper JWT
    const dummyTokens = {
      refreshToken: "initialRefresh",
      username: "testuser",
      expireAt: new Date(Date.now() + 60000),
      authMethod: "REDIRECT" as const,
      accessToken: createMockJWT({
        sub: "user123",
        username: "testuser",
        exp: Math.floor(Date.now() / 1000) + 3600,
        iat: Math.floor(Date.now() / 1000),
      }),
    };

    // Invoke two concurrent refreshTokens calls
    const p1 = refreshTokens({ tokens: dummyTokens });
    const p2 = refreshTokens({ tokens: dummyTokens });

    await Promise.all([p1, p2]);

    // Verify that the stub was called sequentially (locking) not in parallel
    expect(callOrder).toEqual([1, 2]);
  });
});
