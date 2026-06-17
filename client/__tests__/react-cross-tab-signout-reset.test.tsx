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
import { renderHook, act, waitFor } from "@testing-library/react";
import {
  PasswordlessContextProvider,
  usePasswordless,
} from "../react/hooks.js";
import { configure } from "../config.js";
import { retrieveTokens } from "../storage.js";
import { signOut as signOutCore } from "../common.js";
import { getUser } from "../cognito-api.js";
import { authenticateWithFido2 as authenticateWithFido2Core } from "../fido2.js";
import type { TokensFromSignIn } from "../model.js";

// Mocks
jest.mock("../config");
jest.mock("../storage");
jest.mock("../common");
jest.mock("../cognito-api");
jest.mock("../hosted-oauth");
jest.mock("../fido2", () => {
  const actual = jest.requireActual("../fido2");
  return {
    ...actual,
    authenticateWithFido2: jest.fn(),
  };
});

const CLIENT_ID = "test-client-id";
const ACCESS_TOKEN_KEY = `CognitoIdentityServiceProvider.${CLIENT_ID}.user-a.accessToken`;
const LAST_AUTH_USER_KEY = `CognitoIdentityServiceProvider.${CLIENT_ID}.LastAuthUser`;

const mockConfigure = configure as jest.MockedFunction<typeof configure>;
const mockRetrieveTokens = retrieveTokens as jest.MockedFunction<
  typeof retrieveTokens
>;
const mockSignOutCore = signOutCore as jest.MockedFunction<typeof signOutCore>;
const mockGetUser = getUser as jest.MockedFunction<typeof getUser>;
const mockAuthenticateWithFido2 =
  authenticateWithFido2Core as jest.MockedFunction<
    typeof authenticateWithFido2Core
  >;

const makeWrapper = () =>
  function Wrapper({ children }: { children: React.ReactNode }) {
    return (
      <PasswordlessContextProvider>{children}</PasswordlessContextProvider>
    );
  };

const signInTokens: TokensFromSignIn = {
  accessToken: "mock-access-token", // parseable via parseJwtPayload mock in setup.ts
  idToken: "mock-id-token",
  refreshToken: "mock-refresh-token",
  expireAt: new Date(Date.now() + 3600_000),
  username: "user-a",
  authMethod: "FIDO2",
  deviceKey: "us-west-2_device-key-user-a",
};

// Sign the hook's user A in and wait for per-user state to populate.
async function signInUserA(result: {
  current: ReturnType<typeof usePasswordless>;
}) {
  let capturedTokensCb:
    | ((tokens: TokensFromSignIn) => void | Promise<void>)
    | undefined;
  mockAuthenticateWithFido2.mockImplementation((props) => {
    capturedTokensCb = props?.tokensCb;
    return {
      signedIn: Promise.resolve(signInTokens),
      abort: jest.fn(),
    };
  });

  await act(async () => {
    await new Promise((r) => setTimeout(r, 0));
  });

  act(() => {
    result.current.authenticateWithFido2({ username: "user-a" });
  });
  expect(capturedTokensCb).toBeDefined();
  await act(async () => {
    await capturedTokensCb!(signInTokens);
  });

  await waitFor(() => {
    expect(result.current.signInStatus).toBe("SIGNED_IN");
    expect(result.current.deviceKey).toBe("us-west-2_device-key-user-a");
    expect(result.current.totpMfaStatus).toEqual({
      enabled: true,
      preferred: true,
      availableMfaTypes: ["SOFTWARE_TOKEN_MFA"],
    });
    expect(result.current.mfaStatusReady).toBe(true);
  });
}

describe("cross-tab sign-out resets per-user state", () => {
  beforeEach(() => {
    jest.clearAllMocks();

    mockConfigure.mockReturnValue({
      clientId: CLIENT_ID,
      debug: jest.fn(),
      storage: {
        getItem: jest.fn(),
        setItem: jest.fn(),
        removeItem: jest.fn(),
      },
    } as unknown as ReturnType<typeof configure>);

    // After a cross-tab sign-out the local store has no tokens, so the hook's
    // loadTokens (retrieveTokens) resolves undefined.
    mockRetrieveTokens.mockResolvedValue(undefined);

    mockGetUser.mockResolvedValue({
      Username: "user-a",
      UserAttributes: [],
      MFAOptions: [],
      UserMFASettingList: ["SOFTWARE_TOKEN_MFA"],
      PreferredMfaSetting: "SOFTWARE_TOKEN_MFA",
    });

    mockSignOutCore.mockImplementation((props) => {
      props?.statusCb?.("SIGNING_OUT");
      props?.tokensRemovedLocallyCb?.();
      props?.statusCb?.("SIGNED_OUT");
      return {
        signedOut: Promise.resolve(),
        abort: jest.fn(),
      } as unknown as ReturnType<typeof signOutCore>;
    });
  });

  it("resets deviceKey, totpMfaStatus and mfaStatusReady when a token key is removed in another tab", async () => {
    const wrapper = makeWrapper();
    const { result } = renderHook(() => usePasswordless(), { wrapper });

    await signInUserA(result);

    // Another tab signs out: it removes the accessToken key, which fires a
    // `storage` event in THIS tab with newValue === null.
    await act(async () => {
      globalThis.dispatchEvent(
        new StorageEvent("storage", {
          key: ACCESS_TOKEN_KEY,
          oldValue: "some-old-access-token",
          newValue: null,
        })
      );
      await new Promise((r) => setTimeout(r, 0));
    });

    // The SIGN_OUT reducer must have run: all per-user state reset.
    await waitFor(() => {
      expect(result.current.tokens).toBeUndefined();
      expect(result.current.tokensParsed).toBeUndefined();
      expect(result.current.deviceKey).toBeNull();
      expect(result.current.totpMfaStatus).toEqual({
        enabled: false,
        preferred: false,
        availableMfaTypes: [],
      });
      expect(result.current.mfaStatusReady).toBe(false);
    });
  });

  it("resets per-user state when the LastAuthUser key is removed in another tab", async () => {
    const wrapper = makeWrapper();
    const { result } = renderHook(() => usePasswordless(), { wrapper });

    await signInUserA(result);

    await act(async () => {
      globalThis.dispatchEvent(
        new StorageEvent("storage", {
          key: LAST_AUTH_USER_KEY,
          oldValue: "user-a",
          newValue: null,
        })
      );
      await new Promise((r) => setTimeout(r, 0));
    });

    await waitFor(() => {
      expect(result.current.deviceKey).toBeNull();
      expect(result.current.mfaStatusReady).toBe(false);
      expect(result.current.totpMfaStatus).toEqual({
        enabled: false,
        preferred: false,
        availableMfaTypes: [],
      });
    });
  });

  it("does NOT reset per-user state when a token is merely CHANGED (refreshed) in another tab", async () => {
    const wrapper = makeWrapper();
    const { result } = renderHook(() => usePasswordless(), { wrapper });

    await signInUserA(result);

    // After a refresh in another tab, this tab's loadTokens re-reads storage
    // and finds the (rotated) tokens — so the user stays signed in.
    mockRetrieveTokens.mockResolvedValue({
      accessToken: "mock-access-token",
      idToken: "mock-id-token",
      refreshToken: "mock-refresh-token",
      expireAt: new Date(Date.now() + 3600_000),
      username: "user-a",
      authMethod: "FIDO2",
    } as unknown as Awaited<ReturnType<typeof retrieveTokens>>);

    // A token refresh in another tab fires a `storage` event with a NEW
    // (non-null) value. This must only reload tokens, never sign out.
    await act(async () => {
      globalThis.dispatchEvent(
        new StorageEvent("storage", {
          key: ACCESS_TOKEN_KEY,
          oldValue: "some-old-access-token",
          newValue: "some-rotated-access-token",
        })
      );
      await new Promise((r) => setTimeout(r, 0));
    });

    // Per-user state survives a refresh: still signed in, deviceKey intact,
    // MFA status preserved.
    expect(result.current.signInStatus).toBe("SIGNED_IN");
    expect(result.current.deviceKey).toBe("us-west-2_device-key-user-a");
    expect(result.current.mfaStatusReady).toBe(true);
    expect(result.current.totpMfaStatus).toEqual({
      enabled: true,
      preferred: true,
      availableMfaTypes: ["SOFTWARE_TOKEN_MFA"],
    });
  });
});
