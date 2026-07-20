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
import { renderHook, act } from "@testing-library/react";
import {
  PasswordlessContextProvider,
  usePasswordless,
} from "../react/hooks.js";
import { configure } from "../config.js";
import { retrieveTokens, TokensFromStorage } from "../storage.js";
import { getUser } from "../cognito-api.js";

// Mocks
jest.mock("../config");
jest.mock("../storage");
jest.mock("../hosted-oauth");
jest.mock("../cognito-api");
jest.mock("../refresh");
jest.mock("../fido2", () => {
  const actual = jest.requireActual("../fido2");
  return {
    ...actual,
    fido2ListCredentials: jest.fn(() =>
      Promise.resolve({ authenticators: [] })
    ),
  };
});

const mockConfigure = configure as jest.MockedFunction<typeof configure>;
const mockRetrieveTokens = retrieveTokens as jest.MockedFunction<
  typeof retrieveTokens
>;
const mockGetUser = getUser as jest.MockedFunction<typeof getUser>;

// Build a token that the parseJwtPayload mock in setup.ts can decode
const makeJwt = (payload: Record<string, unknown>) =>
  `eyJhbGciOiJub25lIn0.${btoa(JSON.stringify(payload))}.signature`;

// A hosted-UI / OAuth access token: carries only the OAuth scopes that were
// requested, NOT aws.cognito.signin.user.admin
const makeOAuthTokens = (): TokensFromStorage => {
  const expireAt = new Date(Date.now() + 3600_000);
  return {
    accessToken: makeJwt({
      sub: "test-sub",
      username: "test-user",
      exp: Math.floor(expireAt.valueOf() / 1000),
      iat: Math.floor(Date.now() / 1000),
      scope: "openid email profile",
    }),
    idToken: undefined,
    refreshToken: "refresh-token",
    expireAt,
    username: "test-user",
    authMethod: "REDIRECT",
  };
};

const makeWrapper = () =>
  function Wrapper({ children }: { children: React.ReactNode }) {
    return (
      <PasswordlessContextProvider>{children}</PasswordlessContextProvider>
    );
  };

describe("MFA status fetch skipped without aws.cognito.signin.user.admin scope", () => {
  beforeEach(() => {
    jest.useFakeTimers();
    jest.clearAllMocks();

    mockConfigure.mockReturnValue({
      clientId: "test-client-id",
      debug: jest.fn(),
      storage: {
        getItem: jest.fn(),
        setItem: jest.fn(),
        removeItem: jest.fn(),
      },
    } as unknown as ReturnType<typeof configure>);
  });

  afterEach(() => {
    jest.useRealTimers();
  });

  it("never calls getUser and reports default MFA status", async () => {
    mockRetrieveTokens.mockResolvedValue(makeOAuthTokens());

    const wrapper = makeWrapper();
    const { result } = renderHook(() => usePasswordless(), { wrapper });

    await act(async () => {
      await jest.advanceTimersByTimeAsync(0);
    });

    expect(mockGetUser).not.toHaveBeenCalled();
    expect(result.current.mfaStatusReady).toBe(true);
    expect(result.current.totpMfaStatus).toEqual(
      expect.objectContaining({ enabled: false, preferred: false })
    );

    // GetUser can never succeed with this token, so nothing may be scheduled:
    // no retry storm against Cognito
    await act(async () => {
      await jest.advanceTimersByTimeAsync(60_000);
    });
    expect(mockGetUser).not.toHaveBeenCalled();
  });

  it("refreshTotpMfaStatus is a no-op call to Cognito", async () => {
    mockRetrieveTokens.mockResolvedValue(makeOAuthTokens());

    const wrapper = makeWrapper();
    const { result } = renderHook(() => usePasswordless(), { wrapper });

    await act(async () => {
      await jest.advanceTimersByTimeAsync(0);
    });

    await act(async () => {
      await result.current.refreshTotpMfaStatus();
    });

    expect(mockGetUser).not.toHaveBeenCalled();
    expect(result.current.mfaStatusReady).toBe(true);
    expect(result.current.totpMfaStatus).toEqual(
      expect.objectContaining({ enabled: false, preferred: false })
    );
  });
});
