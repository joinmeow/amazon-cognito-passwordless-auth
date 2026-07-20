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
import { refreshTokens } from "../refresh.js";
import { TokensFromRefresh } from "../model.js";

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
const mockRefreshTokens = refreshTokens as jest.MockedFunction<
  typeof refreshTokens
>;

// Build a token that the parseJwtPayload mock in setup.ts can decode
const makeJwt = (payload: Record<string, unknown>) =>
  `eyJhbGciOiJub25lIn0.${btoa(JSON.stringify(payload))}.signature`;

const makeTokens = (suffix: string): TokensFromStorage => {
  const expireAt = new Date(Date.now() + 3600_000);
  return {
    accessToken: makeJwt({
      sub: "test-sub",
      username: "test-user",
      exp: Math.floor(expireAt.valueOf() / 1000),
      iat: Math.floor(Date.now() / 1000),
      jti: suffix,
      scope: "aws.cognito.signin.user.admin",
    }),
    idToken: undefined,
    refreshToken: `refresh-token-${suffix}`,
    expireAt,
    username: "test-user",
    authMethod: "REDIRECT",
  };
};

// Helper wrapper to mount the hook with the provider
const makeWrapper = () =>
  function Wrapper({ children }: { children: React.ReactNode }) {
    return (
      <PasswordlessContextProvider>{children}</PasswordlessContextProvider>
    );
  };

describe("MFA status fetch cooldown", () => {
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

    mockGetUser.mockResolvedValue({
      Username: "test-user",
      UserAttributes: [],
      UserMFASettingList: [],
    } as unknown as Awaited<ReturnType<typeof getUser>>);
  });

  afterEach(() => {
    jest.useRealTimers();
  });

  it("recovers mfaStatusReady when the access token rotates within the cooldown window", async () => {
    const initialTokens = makeTokens("initial");
    mockRetrieveTokens.mockResolvedValue(initialTokens);

    // Simulate a token refresh that rotates the access token
    const rotatedTokens = makeTokens("rotated") as TokensFromRefresh;
    mockRefreshTokens.mockImplementation(async (args) => {
      await args?.tokensCb?.(rotatedTokens);
      return rotatedTokens;
    });

    const wrapper = makeWrapper();
    const { result } = renderHook(() => usePasswordless(), { wrapper });

    // Let the initial effects run: tokens load, getUser fetches MFA status
    await act(async () => {
      await jest.advanceTimersByTimeAsync(0);
    });
    expect(mockGetUser).toHaveBeenCalledTimes(1);
    expect(result.current.mfaStatusReady).toBe(true);

    // 2 seconds later (within the 5s cooldown) the access token rotates,
    // e.g. an OAuth code exchange or forceRefreshTokens completes
    await act(async () => {
      await jest.advanceTimersByTimeAsync(2_000);
    });
    await act(async () => {
      await result.current.refreshTokens();
    });

    // The token change resets mfaStatusReady, and the cooldown blocks an
    // immediate re-fetch
    expect(result.current.mfaStatusReady).toBe(false);
    expect(mockGetUser).toHaveBeenCalledTimes(1);

    // Once the cooldown elapses, the fetch must run again on its own
    // (without the fix, no dependency changes and this deadlocks at false)
    await act(async () => {
      await jest.advanceTimersByTimeAsync(3_100);
    });
    expect(mockGetUser).toHaveBeenCalledTimes(2);
    expect(mockGetUser).toHaveBeenLastCalledWith(
      expect.objectContaining({ accessToken: rotatedTokens.accessToken })
    );
    expect(result.current.mfaStatusReady).toBe(true);

    // No fetch storm: nothing further is scheduled once status is known
    await act(async () => {
      await jest.advanceTimersByTimeAsync(30_000);
    });
    expect(mockGetUser).toHaveBeenCalledTimes(2);
  });

  it("stops retrying MFA status fetch after the cap when getUser keeps failing", async () => {
    mockRetrieveTokens.mockResolvedValue(makeTokens("initial"));
    // getUser fails every time (e.g. a network outage or a backend erroring)
    mockGetUser.mockRejectedValue(new Error("network down"));

    const wrapper = makeWrapper();
    const { result } = renderHook(() => usePasswordless(), { wrapper });

    // Initial attempt
    await act(async () => {
      await jest.advanceTimersByTimeAsync(0);
    });
    expect(mockGetUser).toHaveBeenCalledTimes(1);
    // Even on failure the UI is unblocked (last-known status retained)
    expect(result.current.mfaStatusReady).toBe(true);

    // Drive well past many retry windows (each retry is 6–8s jittered).
    // The cap is 3 retries, so a total of 1 initial + 3 retries = 4 fetches,
    // after which it must stop — not poll forever.
    for (let i = 0; i < 12; i++) {
      await act(async () => {
        await jest.advanceTimersByTimeAsync(8_000);
      });
    }

    expect(mockGetUser).toHaveBeenCalledTimes(4);

    // A genuinely new token resets the budget and fetches again
    mockGetUser.mockClear();
    mockGetUser.mockRejectedValue(new Error("still down"));
    const rotated = makeTokens("rotated") as TokensFromRefresh;
    mockRefreshTokens.mockImplementation(async (args) => {
      await args?.tokensCb?.(rotated);
      return rotated;
    });
    await act(async () => {
      await result.current.refreshTokens();
    });
    await act(async () => {
      await jest.advanceTimersByTimeAsync(0);
    });
    // The new token gets its own first fetch (budget reset)
    expect(mockGetUser).toHaveBeenCalled();
  });
});
