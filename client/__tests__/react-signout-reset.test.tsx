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

// Helper wrapper to mount the hook with the provider
const makeWrapper = () =>
  function Wrapper({ children }: { children: React.ReactNode }) {
    return (
      <PasswordlessContextProvider>{children}</PasswordlessContextProvider>
    );
  };

describe("signOut resets per-user state", () => {
  beforeEach(() => {
    jest.clearAllMocks();

    // Minimal default config for tests
    mockConfigure.mockReturnValue({
      clientId: "test-client-id",
      debug: jest.fn(),
      storage: {
        getItem: jest.fn(),
        setItem: jest.fn(),
        removeItem: jest.fn(),
      },
    } as unknown as ReturnType<typeof configure>);

    // No cached tokens at mount
    mockRetrieveTokens.mockResolvedValue(undefined);

    // getUser reports user A has TOTP MFA enabled and preferred
    mockGetUser.mockResolvedValue({
      Username: "user-a",
      UserAttributes: [],
      MFAOptions: [],
      UserMFASettingList: ["SOFTWARE_TOKEN_MFA"],
      PreferredMfaSetting: "SOFTWARE_TOKEN_MFA",
    });

    // Core signOut invokes the local-removal callback like the real one does
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

  it("clears deviceKey, totpMfaStatus and mfaStatusReady on signOut", async () => {
    const signInTokens: TokensFromSignIn = {
      accessToken: "mock-access-token", // parseable via parseJwtPayload mock in setup.ts
      idToken: "mock-id-token",
      refreshToken: "mock-refresh-token",
      expireAt: new Date(Date.now() + 3600_000),
      username: "user-a",
      authMethod: "FIDO2",
      deviceKey: "us-west-2_device-key-user-a",
    };

    // Capture the hook's tokensCb so we can drive a sign-in with a deviceKey
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

    const wrapper = makeWrapper();
    const { result } = renderHook(() => usePasswordless(), { wrapper });

    // Wait for initial token retrieval to settle
    await act(async () => {
      await new Promise((r) => setTimeout(r, 0));
    });

    // Sign user A in (the mocked core flow hands tokens to the hook)
    act(() => {
      result.current.authenticateWithFido2({ username: "user-a" });
    });
    expect(capturedTokensCb).toBeDefined();
    await act(async () => {
      await capturedTokensCb!(signInTokens);
    });

    // Per-user state is populated for user A
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

    // Sign out
    await act(async () => {
      await result.current.signOut().signedOut;
    });

    // All per-user state must be reset so it cannot leak to the next user
    expect(result.current.tokens).toBeUndefined();
    expect(result.current.tokensParsed).toBeUndefined();
    expect(result.current.fido2Credentials).toBeUndefined();
    expect(result.current.deviceKey).toBeNull();
    expect(result.current.totpMfaStatus).toEqual({
      enabled: false,
      preferred: false,
      availableMfaTypes: [],
    });
    expect(result.current.mfaStatusReady).toBe(false);
    expect(result.current.signInStatus).toBe("NOT_SIGNED_IN");
  });

  it("discards an in-flight getUser response that lands after signOut", async () => {
    // Regression: a getUser response resolving in the microtask gap between
    // the SIGN_OUT dispatch and React's effect cleanup (which aborts the
    // fetch) used to re-dispatch the previous user's MFA status while
    // signed out.
    type GetUserResult = Awaited<ReturnType<typeof getUser>>;
    let resolveGetUser: ((user: GetUserResult) => void) | undefined;
    mockGetUser.mockImplementation(
      () =>
        new Promise<GetUserResult>((resolve) => {
          resolveGetUser = resolve;
        })
    );

    const signInTokens: TokensFromSignIn = {
      accessToken: "mock-access-token",
      idToken: "mock-id-token",
      refreshToken: "mock-refresh-token",
      expireAt: new Date(Date.now() + 3600_000),
      username: "user-a",
      authMethod: "FIDO2",
    };
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

    const wrapper = makeWrapper();
    const { result } = renderHook(() => usePasswordless(), { wrapper });
    await act(async () => {
      await new Promise((r) => setTimeout(r, 0));
    });

    // Sign in; the MFA fetch starts and stays pending
    act(() => {
      result.current.authenticateWithFido2({ username: "user-a" });
    });
    await act(async () => {
      await capturedTokensCb!(signInTokens);
    });
    await waitFor(() => {
      expect(result.current.signInStatus).toBe("SIGNED_IN");
    });
    expect(resolveGetUser).toBeDefined();
    expect(result.current.mfaStatusReady).toBe(false);

    // Sign out, and let the stale getUser response land in the microtask
    // gap after the SIGN_OUT dispatch but before the effect cleanup aborts
    await act(async () => {
      const signingOut = result.current.signOut();
      resolveGetUser!({
        Username: "user-a",
        UserAttributes: [],
        MFAOptions: [],
        UserMFASettingList: ["SOFTWARE_TOKEN_MFA"],
        PreferredMfaSetting: "SOFTWARE_TOKEN_MFA",
      });
      await signingOut.signedOut;
    });

    // The stale response must not restore the previous user's MFA status
    expect(result.current.totpMfaStatus).toEqual({
      enabled: false,
      preferred: false,
      availableMfaTypes: [],
    });
    expect(result.current.mfaStatusReady).toBe(false);
  });
});
