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
import { retrieveTokens, getRememberedDevice } from "../storage.js";
import { getUser } from "../cognito-api.js";
import { authenticateWithSRP } from "../srp.js";
import { authenticateWithPlaintextPassword } from "../plaintext.js";
import type { TokensFromSignIn } from "../model.js";

jest.mock("../config");
jest.mock("../storage");
jest.mock("../common");
jest.mock("../cognito-api");
jest.mock("../hosted-oauth");
jest.mock("../srp");
jest.mock("../plaintext");
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
const mockGetRememberedDevice = getRememberedDevice as jest.MockedFunction<
  typeof getRememberedDevice
>;
const mockGetUser = getUser as jest.MockedFunction<typeof getUser>;
const mockAuthSRP = authenticateWithSRP as jest.MockedFunction<
  typeof authenticateWithSRP
>;
const mockAuthPlaintext =
  authenticateWithPlaintextPassword as jest.MockedFunction<
    typeof authenticateWithPlaintextPassword
  >;

// Tokens that DO NOT carry a deviceKey (the common case the rehydrate covers)
const tokensWithoutDeviceKey: TokensFromSignIn = {
  accessToken: "mock-access-token", // parseable via parseJwtPayload mock in setup.ts
  idToken: "mock-id-token",
  refreshToken: "mock-refresh-token",
  expireAt: new Date(Date.now() + 3600_000),
  username: "user-a",
  authMethod: "SRP",
};

const makeWrapper = () =>
  function Wrapper({ children }: { children: React.ReactNode }) {
    return (
      <PasswordlessContextProvider>{children}</PasswordlessContextProvider>
    );
  };

describe("deviceKey rehydration in SRP / plaintext tokensCb", () => {
  beforeEach(() => {
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
    mockRetrieveTokens.mockResolvedValue(undefined);
    mockGetUser.mockResolvedValue({
      Username: "user-a",
      UserAttributes: [],
      UserMFASettingList: [],
    } as unknown as Awaited<ReturnType<typeof getUser>>);
    // A remembered device exists in storage for this user
    mockGetRememberedDevice.mockResolvedValue({
      deviceKey: "us-west-2_remembered-device",
      groupKey: "grp",
      password: "pw",
      remembered: true,
    });
  });

  const driveSignIn = async (
    result: { current: ReturnType<typeof usePasswordless> },
    method: "srp" | "plaintext"
  ) => {
    let capturedTokensCb:
      | ((tokens: TokensFromSignIn) => void | Promise<void>)
      | undefined;
    const impl = (props: { tokensCb?: typeof capturedTokensCb }) => {
      capturedTokensCb = props?.tokensCb;
      return {
        signedIn: Promise.resolve(tokensWithoutDeviceKey),
        abort: jest.fn(),
      };
    };
    if (method === "srp") {
      mockAuthSRP.mockImplementation(impl as never);
    } else {
      mockAuthPlaintext.mockImplementation(impl as never);
    }

    await act(async () => {
      await new Promise((r) => setTimeout(r, 0));
    });
    act(() => {
      if (method === "srp") {
        result.current.authenticateWithSRP({
          username: "user-a",
          password: "pw",
        });
      } else {
        result.current.authenticateWithPlaintextPassword({
          username: "user-a",
          password: "pw",
        });
      }
    });
    expect(capturedTokensCb).toBeDefined();
    await act(async () => {
      await capturedTokensCb!(tokensWithoutDeviceKey);
    });
  };

  it("rehydrates deviceKey from the remembered device on SRP sign-in when tokens omit it", async () => {
    const { result } = renderHook(() => usePasswordless(), {
      wrapper: makeWrapper(),
    });
    await driveSignIn(result, "srp");

    await waitFor(() => {
      expect(result.current.deviceKey).toBe("us-west-2_remembered-device");
    });
    expect(mockGetRememberedDevice).toHaveBeenCalledWith("user-a");
  });

  it("rehydrates deviceKey from the remembered device on plaintext sign-in when tokens omit it", async () => {
    const { result } = renderHook(() => usePasswordless(), {
      wrapper: makeWrapper(),
    });
    await driveSignIn(result, "plaintext");

    await waitFor(() => {
      expect(result.current.deviceKey).toBe("us-west-2_remembered-device");
    });
    expect(mockGetRememberedDevice).toHaveBeenCalledWith("user-a");
  });

  it("does not rehydrate when no remembered device exists (SRP)", async () => {
    mockGetRememberedDevice.mockResolvedValue(undefined);
    const { result } = renderHook(() => usePasswordless(), {
      wrapper: makeWrapper(),
    });
    await driveSignIn(result, "srp");

    await waitFor(() => {
      expect(result.current.signInStatus).toBe("SIGNED_IN");
    });
    expect(result.current.deviceKey).toBeNull();
  });

  it("does not let a stale rehydrate lookup overwrite a newer sign-in's deviceKey", async () => {
    // The rehydrate awaits getRememberedDevice() after the session is already
    // visible. If a newer sign-in (different user, carrying its own deviceKey)
    // lands while user A's lookup is in flight, A's late resolution must NOT
    // overwrite the newer user's deviceKey.
    const tokensA: TokensFromSignIn = {
      ...tokensWithoutDeviceKey,
      username: "user-a",
    };
    const tokensB: TokensFromSignIn = {
      ...tokensWithoutDeviceKey,
      username: "user-b",
      deviceKey: "us-west-2_device-key-user-b",
    };

    // A's remembered-device lookup is deferred so we can complete B's sign-in
    // before it resolves.
    let resolveLookupA!: (rec: {
      deviceKey: string;
      groupKey: string;
      password: string;
      remembered: boolean;
    }) => void;
    mockGetRememberedDevice.mockImplementation(
      () =>
        new Promise((resolve) => {
          resolveLookupA = resolve;
        })
    );

    let capturedTokensCb:
      | ((tokens: TokensFromSignIn) => void | Promise<void>)
      | undefined;
    mockAuthSRP.mockImplementation(((props: {
      tokensCb?: typeof capturedTokensCb;
    }) => {
      capturedTokensCb = props?.tokensCb;
      return {
        signedIn: Promise.resolve(tokensA),
        abort: jest.fn(),
      };
    }) as never);

    const { result } = renderHook(() => usePasswordless(), {
      wrapper: makeWrapper(),
    });
    await act(async () => {
      await new Promise((r) => setTimeout(r, 0));
    });

    act(() => {
      result.current.authenticateWithSRP({
        username: "user-a",
        password: "pw",
      });
    });
    expect(capturedTokensCb).toBeDefined();

    // Drive user A's tokensCb but do NOT await it: it marks the session
    // current (user-a), then suspends on the deferred lookup.
    let tokensADone!: Promise<void>;
    await act(async () => {
      tokensADone = Promise.resolve(capturedTokensCb!(tokensA));
      await Promise.resolve();
    });
    expect(mockGetRememberedDevice).toHaveBeenCalledWith("user-a");

    // A newer sign-in for user B completes (it carries its own deviceKey, so
    // it takes the synchronous path and overwrites the current-session marker).
    await act(async () => {
      await capturedTokensCb!(tokensB);
    });
    expect(result.current.deviceKey).toBe("us-west-2_device-key-user-b");

    // A's lookup resolves too late: the current session is now user B, so the
    // guard must skip A's SET_DEVICE_KEY and leave B's deviceKey untouched.
    await act(async () => {
      resolveLookupA({
        deviceKey: "us-west-2_remembered-device-a",
        groupKey: "grp",
        password: "pw",
        remembered: true,
      });
      await tokensADone;
    });

    expect(result.current.deviceKey).toBe("us-west-2_device-key-user-b");
  });
});
