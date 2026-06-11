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

/*
 * Regression tests for the hook's forgetDevice/clearDeviceKey: they must
 * clear the per-user remembered-device record (the one retrieveDeviceKey()
 * reads on subsequent sign-ins), not just the legacy
 * `Passwordless.<clientId>.deviceKey` entry. A surviving record would be
 * sent as a stale DEVICE_KEY on the next sign-in.
 */

import React from "react";
import { renderHook, act } from "@testing-library/react";
import {
  PasswordlessContextProvider,
  usePasswordless,
} from "../react/hooks.js";
import { configure } from "../config.js";
import {
  retrieveTokens,
  onTokensStored,
  clearRememberedDevice,
} from "../storage.js";
import { forgetDevice as forgetDeviceApi } from "../cognito-api.js";
import { authenticateWithFido2 as authenticateWithFido2Core } from "../fido2.js";
import type { TokensFromSignIn } from "../model.js";

jest.mock("../config");
jest.mock("../storage");
jest.mock("../hosted-oauth");
jest.mock("../cognito-api", () => ({
  verifySoftwareTokenForCurrentUser: jest.fn(),
  associateSoftwareTokenForCurrentUser: jest.fn(),
  confirmDevice: jest.fn(),
  updateDeviceStatus: jest.fn(),
  forgetDevice: jest.fn(),
  getUser: jest.fn(() => new Promise(() => {})),
}));
jest.mock("../fido2", () => {
  // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
  const actual = jest.requireActual("../fido2");
  return {
    ...(actual as object),
    authenticateWithFido2: jest.fn(),
    prepareFido2SignIn: jest.fn(),
  };
});

const mockConfigure = configure as jest.MockedFunction<typeof configure>;
const mockRetrieveTokens = retrieveTokens as jest.MockedFunction<
  typeof retrieveTokens
>;
const mockOnTokensStored = onTokensStored as jest.MockedFunction<
  typeof onTokensStored
>;
const mockClearRememberedDevice = clearRememberedDevice as jest.MockedFunction<
  typeof clearRememberedDevice
>;
const mockForgetDeviceApi = forgetDeviceApi as jest.MockedFunction<
  typeof forgetDeviceApi
>;
const mockAuthenticateWithFido2 =
  authenticateWithFido2Core as jest.MockedFunction<
    typeof authenticateWithFido2Core
  >;

const USERNAME = "canonical-user-sub";
const DEVICE_KEY = "us-east-1_device-1";

const futureDate = () => new Date(Date.now() + 3600 * 1000);

/** A parseable JWT (the hook parses access and id tokens into state) */
function makeJwt(payload: Record<string, unknown>) {
  return `${btoa(JSON.stringify({ alg: "none" }))}.${btoa(
    JSON.stringify(payload)
  )}.signature`;
}

const ACCESS_TOKEN = makeJwt({
  username: USERNAME,
  exp: Math.floor(Date.now() / 1000) + 3600,
});
const ID_TOKEN = makeJwt({
  sub: USERNAME,
  "cognito:username": USERNAME,
  exp: Math.floor(Date.now() / 1000) + 3600,
});

const makeWrapper = () =>
  function Wrapper({ children }: { children: React.ReactNode }) {
    return (
      <PasswordlessContextProvider>{children}</PasswordlessContextProvider>
    );
  };

beforeEach(() => {
  jest.clearAllMocks();

  mockConfigure.mockReturnValue({
    clientId: "test-client-id",
    debug: undefined,
    storage: {
      getItem: jest.fn(),
      setItem: jest.fn(),
      removeItem: jest.fn(),
    },
  } as unknown as ReturnType<typeof configure>);

  mockRetrieveTokens.mockResolvedValue(undefined);
  mockOnTokensStored.mockReturnValue(() => {});
  mockClearRememberedDevice.mockResolvedValue(undefined);
  mockForgetDeviceApi.mockResolvedValue({
    ok: true,
    json: () => Promise.resolve({}),
  } as unknown as Awaited<ReturnType<typeof forgetDeviceApi>>);
});

/** Sign in via the (mocked) FIDO2 flow so the hook holds tokens + deviceKey state */
async function signInWithDevice(
  result: { current: ReturnType<typeof usePasswordless> },
  deviceKey: string | undefined = DEVICE_KEY
) {
  const tokens: TokensFromSignIn = {
    accessToken: ACCESS_TOKEN,
    idToken: ID_TOKEN,
    refreshToken: "mock-refresh-token",
    expireAt: futureDate(),
    username: USERNAME,
    deviceKey,
    authMethod: "FIDO2",
  };
  mockAuthenticateWithFido2.mockImplementation(
    ({ tokensCb } = {} as never) => ({
      signedIn: (async () => {
        await tokensCb?.(tokens);
        return tokens;
      })(),
      abort: jest.fn(),
    })
  );
  // Let the mount-time token restoration settle first, so it cannot race
  // with (and overwrite) the sign-in below
  await act(async () => {
    await new Promise((r) => setTimeout(r, 0));
  });
  await act(async () => {
    await result.current.authenticateWithFido2({ username: USERNAME })
      .signedIn;
  });
}

describe("usePasswordless forgetDevice / clearDeviceKey", () => {
  it("forgetDevice clears the per-user remembered-device record after server-side ForgetDevice", async () => {
    const wrapper = makeWrapper();
    const { result } = renderHook(() => usePasswordless(), { wrapper });
    await signInWithDevice(result);
    expect(result.current.deviceKey).toBe(DEVICE_KEY);

    await act(async () => {
      await result.current.forgetDevice();
    });

    expect(mockForgetDeviceApi).toHaveBeenCalledWith({
      accessToken: ACCESS_TOKEN,
      deviceKey: DEVICE_KEY,
    });
    // The per-user record (read by retrieveDeviceKey on the next sign-in)
    // must be gone, so the forgotten key is never sent again
    expect(mockClearRememberedDevice).toHaveBeenCalledWith(USERNAME);
    expect(result.current.deviceKey).toBeNull();
  });

  it("clearDeviceKey clears the per-user remembered-device record locally", async () => {
    const wrapper = makeWrapper();
    const { result } = renderHook(() => usePasswordless(), { wrapper });
    await signInWithDevice(result);

    // clearDeviceKey awaits the storage removal: once it resolves, a
    // sign-in started immediately afterwards cannot read the old record
    await act(async () => {
      await result.current.clearDeviceKey();
    });

    expect(mockClearRememberedDevice).toHaveBeenCalledWith(USERNAME);
    expect(result.current.deviceKey).toBeNull();
  });
});
