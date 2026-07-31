/**
 * Copyright Amazon.com, Inc. and its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"). You
 * may not use this file except in compliance with the License. A copy of
 * the License is located at
 *
 *     http://aws.amazon.com/apache2.0/
 *
 * or in the "license" file accompanying this file. This file is
 * distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF
 * ANY KIND, either express or implied. See the License for the specific
 * language governing permissions and limitations under the License.
 */
import React from "react";
import { render, screen, waitFor, act, cleanup } from "@testing-library/react";
import { configure } from "../config.js";
import type { MinimalFetch } from "../config.js";
import { storeTokens } from "../storage.js";
import {
  PasswordlessContextProvider,
  usePasswordless,
} from "../react/hooks.js";

// Phase 4: MFA readiness is DERIVED from the resolved access-token identity
// (state.mfaStatusReadyForToken === current access token), not a plain boolean
// that updateTokens could reset. This removes the permanent post-login spinner:
// a stale updateTokens closure can no longer un-ready an already-resolved token,
// and a getUser response for a superseded token cannot ready a newer one.

const enc = (obj: unknown) =>
  btoa(JSON.stringify(obj))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
const createJWT = (claims: Record<string, unknown>) =>
  `${enc({ alg: "HS256", typ: "JWT" })}.${enc(claims)}.sig`;

const USERNAME = "testuser";
function accessToken(opts: { adminScope: boolean; jti?: string }) {
  const now = Math.floor(Date.now() / 1000);
  return createJWT({
    sub: "user123",
    username: USERNAME,
    jti: opts.jti ?? "a",
    scope: opts.adminScope
      ? "aws.cognito.signin.user.admin openid"
      : "openid email",
    exp: now + 3600,
    iat: now,
  });
}

function createMemoryStorage() {
  const store = new Map<string, string>();
  return {
    getItem: (k: string) => store.get(k) ?? null,
    setItem: (k: string, v: string) => {
      store.set(k, v);
    },
    removeItem: (k: string) => {
      store.delete(k);
    },
  };
}

// A fetch mock that answers GetUser (and lets the test observe / gate it), and
// returns a benign 200 for anything else the provider touches on mount.
function makeFetch(
  opts: {
    getUser?: () => Promise<{ ok: boolean; status: number; body: unknown }>;
  } = {}
) {
  const state = { getUserCalls: 0 };
  const fetchMock = jest.fn(
    async (_url: unknown, init?: { headers?: Record<string, string> }) => {
      const target = init?.headers?.["x-amz-target"] ?? "";
      if (target.endsWith("GetUser")) {
        state.getUserCalls++;
        const res = opts.getUser
          ? await opts.getUser()
          : {
              ok: true,
              status: 200,
              body: {
                Username: USERNAME,
                UserAttributes: [],
                UserMFASettingList: [],
              },
            };
        return {
          ok: res.ok,
          status: res.status,
          json: async () => res.body,
        };
      }
      return { ok: true, status: 200, json: async () => ({}) };
    }
  );
  return { fetchMock, state };
}

function Probe() {
  const {
    mfaStatusReady,
    tokens,
    signOut,
    totpMfaStatus,
    refreshTotpMfaStatus,
  } = usePasswordless();
  return (
    <div>
      <span data-testid="ready">{String(mfaStatusReady)}</span>
      <span data-testid="token">{tokens?.accessToken ?? "none"}</span>
      <span data-testid="mfa-enabled">{String(totpMfaStatus.enabled)}</span>
      <button data-testid="signout" onClick={() => void signOut()}>
        out
      </button>
      <button
        data-testid="refresh-mfa"
        onClick={() => void refreshTotpMfaStatus()}
      >
        refresh
      </button>
    </div>
  );
}

const renderProbe = () =>
  render(
    <PasswordlessContextProvider>
      <Probe />
    </PasswordlessContextProvider>
  );

const ready = () => screen.getByTestId("ready").textContent;

async function seedSession(adminScope: boolean, jti = "a") {
  await storeTokens({
    accessToken: accessToken({ adminScope, jti }),
    idToken: createJWT({
      sub: "user123",
      "cognito:username": USERNAME,
      exp: Math.floor(Date.now() / 1000) + 3600,
      iat: Math.floor(Date.now() / 1000),
    }),
    refreshToken: `refresh-${jti}`,
    authMethod: "SRP",
    expireAt: new Date(Date.now() + 3600_000),
  });
}

describe("MFA status readiness (derived from token identity)", () => {
  afterEach(() => {
    cleanup();
    jest.useRealTimers();
  });

  test("becomes ready once getUser resolves for the signed-in token", async () => {
    const { fetchMock, state } = makeFetch();
    configure({
      clientId: "testClient",
      cognitoIdpEndpoint: "us-west-2",
      storage: createMemoryStorage(),
      fetch: fetchMock as unknown as MinimalFetch,
    });
    await seedSession(true);

    renderProbe();
    await waitFor(() => expect(ready()).toBe("true"));
    expect(state.getUserCalls).toBe(1);
  });

  test("a token lacking the admin scope reaches ready WITHOUT calling getUser", async () => {
    const { fetchMock, state } = makeFetch();
    configure({
      clientId: "testClient",
      cognitoIdpEndpoint: "us-west-2",
      storage: createMemoryStorage(),
      fetch: fetchMock as unknown as MinimalFetch,
    });
    await seedSession(false);

    renderProbe();
    await waitFor(() => expect(ready()).toBe("true"));
    expect(state.getUserCalls).toBe(0);
  });

  test("a getUser failure still reaches ready (fail-open, never hangs)", async () => {
    // json() rejecting makes getUser reject OUTSIDE the fetch retry wrapper, so
    // it fails fast (a 5xx would be retried for seconds) and exercises the
    // effect's catch → still-ready path.
    const fetchMock = jest.fn(
      async (_url: unknown, init?: { headers?: Record<string, string> }) => {
        if ((init?.headers?.["x-amz-target"] ?? "").endsWith("GetUser")) {
          return {
            ok: true,
            status: 200,
            json: async () => {
              throw new Error("boom");
            },
          };
        }
        return { ok: true, status: 200, json: async () => ({}) };
      }
    );
    configure({
      clientId: "testClient",
      cognitoIdpEndpoint: "us-west-2",
      storage: createMemoryStorage(),
      fetch: fetchMock as unknown as MinimalFetch,
    });
    await seedSession(true);

    renderProbe();
    await waitFor(() => expect(ready()).toBe("true"));
  });

  test("sign-out clears readiness (derived false once tokens are gone)", async () => {
    const { fetchMock } = makeFetch();
    configure({
      clientId: "testClient",
      cognitoIdpEndpoint: "us-west-2",
      storage: createMemoryStorage(),
      fetch: fetchMock as unknown as MinimalFetch,
    });
    await seedSession(true);

    renderProbe();
    await waitFor(() => expect(ready()).toBe("true"));

    await act(async () => {
      screen.getByTestId("signout").click();
    });
    await waitFor(() =>
      expect(screen.getByTestId("token").textContent).toBe("none")
    );
    expect(ready()).toBe("false");
  });

  test("a refreshTotpMfaStatus response landing after sign-out cannot overwrite the reset MFA status", async () => {
    // First GetUser (the mount effect) resolves immediately with MFA disabled;
    // the second (manual refreshTotpMfaStatus) is gated and answers MFA
    // ENABLED — but only after the user has signed out. Without the
    // cross-session guard, that stale answer would overwrite the reset state.
    let releaseSecond!: () => void;
    const gate = new Promise<void>((r) => {
      releaseSecond = r;
    });
    let getUserCalls = 0;
    const { fetchMock } = makeFetch({
      getUser: async () => {
        getUserCalls++;
        if (getUserCalls >= 2) await gate;
        return {
          ok: true,
          status: 200,
          body: {
            Username: USERNAME,
            UserAttributes: [],
            UserMFASettingList: getUserCalls >= 2 ? ["SOFTWARE_TOKEN_MFA"] : [],
            ...(getUserCalls >= 2 && {
              PreferredMfaSetting: "SOFTWARE_TOKEN_MFA",
            }),
          },
        };
      },
    });
    configure({
      clientId: "testClient",
      cognitoIdpEndpoint: "us-west-2",
      storage: createMemoryStorage(),
      fetch: fetchMock as unknown as MinimalFetch,
    });
    await seedSession(true);

    renderProbe();
    await waitFor(() => expect(ready()).toBe("true"));

    // Kick off the manual refresh (gated), then sign out while it is pending.
    await act(async () => {
      screen.getByTestId("refresh-mfa").click();
    });
    await act(async () => {
      screen.getByTestId("signout").click();
    });
    await waitFor(() =>
      expect(screen.getByTestId("token").textContent).toBe("none")
    );

    // Stale MFA-ENABLED answer lands after the SIGN_OUT reset.
    await act(async () => {
      releaseSecond();
      await Promise.resolve();
    });

    // The reset state must survive: no session-A bleed into the reset state.
    expect(screen.getByTestId("mfa-enabled").textContent).toBe("false");
    expect(ready()).toBe("false");
  });

  test("a getUser response that lands after sign-out cannot mark a signed-out session ready", async () => {
    let releaseGetUser!: () => void;
    const gate = new Promise<void>((r) => {
      releaseGetUser = r;
    });
    const { fetchMock } = makeFetch({
      getUser: async () => {
        await gate;
        return {
          ok: true,
          status: 200,
          body: {
            Username: USERNAME,
            UserAttributes: [],
            UserMFASettingList: ["SOFTWARE_TOKEN_MFA"],
          },
        };
      },
    });
    configure({
      clientId: "testClient",
      cognitoIdpEndpoint: "us-west-2",
      storage: createMemoryStorage(),
      fetch: fetchMock as unknown as MinimalFetch,
    });
    await seedSession(true);

    renderProbe();
    // getUser is in flight and gated → not ready yet.
    await waitFor(() =>
      expect(screen.getByTestId("token").textContent).not.toBe("none")
    );
    expect(ready()).toBe("false");

    // Sign out while getUser is pending, then let the stale response land.
    await act(async () => {
      screen.getByTestId("signout").click();
    });
    await waitFor(() =>
      expect(screen.getByTestId("token").textContent).toBe("none")
    );
    await act(async () => {
      releaseGetUser();
      await Promise.resolve();
    });

    // The signed-out session must not be marked ready by session A's response.
    expect(ready()).toBe("false");
  });
});
