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

import { authenticateWithPlaintextPassword } from "../plaintext.js";
import { configure } from "../config.js";
import { setRememberedDevice } from "../storage.js";
import { initiateAuth, handleAuthResponse } from "../cognito-api.js";
import { processTokens } from "../common.js";

jest.mock("../cognito-api.js", () => {
  // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
  const actual = jest.requireActual("../cognito-api.js");
  return {
    ...(actual as object),
    initiateAuth: jest.fn(),
    handleAuthResponse: jest.fn(),
  };
});

jest.mock("../common.js", () => ({
  processTokens: jest.fn(),
}));

const mockInitiateAuth = initiateAuth as jest.MockedFunction<
  typeof initiateAuth
>;
const mockHandleAuthResponse = handleAuthResponse as jest.MockedFunction<
  typeof handleAuthResponse
>;
const mockProcessTokens = processTokens as jest.MockedFunction<
  typeof processTokens
>;

const CANONICAL_USER_ID = "canonical-user-sub";
const ALIAS_USERNAME = "alias@example.com";

function createMemoryStorage() {
  const store = new Map<string, string>();
  return {
    getItem: (key: string) => store.get(key) ?? null,
    setItem: (key: string, value: string) => {
      store.set(key, value);
    },
    removeItem: (key: string) => {
      store.delete(key);
    },
  };
}

function mockChallengeResponse(
  challengeParameters: Record<string, string> = {
    USER_ID_FOR_SRP: CANONICAL_USER_ID,
  }
) {
  mockInitiateAuth.mockResolvedValue({
    ChallengeName: "SMS_MFA",
    ChallengeParameters: challengeParameters,
    Session: "test-session",
  } as unknown as Awaited<ReturnType<typeof initiateAuth>>);
}

function mockAuthenticatedResponse() {
  // Access token whose payload carries the canonical username claim
  const accessToken = `${btoa(JSON.stringify({ alg: "none" }))}.${btoa(
    JSON.stringify({
      username: CANONICAL_USER_ID,
      exp: Math.floor(Date.now() / 1000) + 3600,
    })
  )}.signature`;
  mockInitiateAuth.mockResolvedValue({
    AuthenticationResult: {
      AccessToken: accessToken,
      IdToken: "test-id-token",
      RefreshToken: "test-refresh-token",
      ExpiresIn: 3600,
      TokenType: "Bearer",
    },
    ChallengeParameters: {},
  } as unknown as Awaited<ReturnType<typeof initiateAuth>>);
}

describe("plaintext flow device record lookup", () => {
  beforeEach(() => {
    jest.clearAllMocks();
    configure({
      clientId: "test-client",
      userPoolId: "us-east-1_testpool",
      storage: createMemoryStorage(),
    });
    mockHandleAuthResponse.mockImplementation(({ username }) =>
      Promise.resolve({
        accessToken: "mock-access-token",
        idToken: "mock-id-token",
        refreshToken: "mock-refresh-token",
        expireAt: new Date(Date.now() + 3600 * 1000),
        username,
        deviceKey: undefined,
        newDeviceMetadata: undefined,
      })
    );
    mockProcessTokens.mockImplementation((tokens) => Promise.resolve(tokens));
  });

  it("finds a device record stored under the canonical user id when signing in with an alias", async () => {
    // Device confirmed during an SRP sign-in is stored under the canonical user id
    await setRememberedDevice(CANONICAL_USER_ID, {
      deviceKey: "us-east-1_device-1",
      groupKey: "group-key-1",
      password: "device-password-1",
      remembered: true,
    });
    mockChallengeResponse();

    const { signedIn } = authenticateWithPlaintextPassword({
      username: ALIAS_USERNAME,
      password: "secret",
      smsMfaCode: () => Promise.resolve("123456"),
    });
    await signedIn;

    expect(mockHandleAuthResponse).toHaveBeenCalledTimes(1);
    const callArgs = mockHandleAuthResponse.mock.calls[0][0];
    expect(callArgs.username).toBe(CANONICAL_USER_ID);
    expect(callArgs.deviceHandler?.deviceKey).toBe("us-east-1_device-1");
  });

  it("falls back to a legacy device record stored under the username as entered", async () => {
    // Device record stored by previous versions, keyed by the alias
    await setRememberedDevice(ALIAS_USERNAME, {
      deviceKey: "us-east-1_device-2",
      groupKey: "group-key-2",
      password: "device-password-2",
      remembered: true,
    });
    mockChallengeResponse();

    const { signedIn } = authenticateWithPlaintextPassword({
      username: ALIAS_USERNAME,
      password: "secret",
      smsMfaCode: () => Promise.resolve("123456"),
    });
    await signedIn;

    expect(mockHandleAuthResponse).toHaveBeenCalledTimes(1);
    const callArgs = mockHandleAuthResponse.mock.calls[0][0];
    // Challenges still use the canonical user id ...
    expect(callArgs.username).toBe(CANONICAL_USER_ID);
    // ... while the legacy device record is found via the fallback lookup
    expect(callArgs.deviceHandler?.deviceKey).toBe("us-east-1_device-2");
  });

  it("resolves the canonical user id from the access token for authenticated responses", async () => {
    await setRememberedDevice(CANONICAL_USER_ID, {
      deviceKey: "us-east-1_device-3",
      groupKey: "group-key-3",
      password: "device-password-3",
      remembered: true,
    });
    mockAuthenticatedResponse();

    const { signedIn } = authenticateWithPlaintextPassword({
      username: ALIAS_USERNAME,
      password: "secret",
    });
    await signedIn;

    expect(mockHandleAuthResponse).toHaveBeenCalledTimes(1);
    const callArgs = mockHandleAuthResponse.mock.calls[0][0];
    expect(callArgs.username).toBe(CANONICAL_USER_ID);
    expect(callArgs.deviceHandler?.deviceKey).toBe("us-east-1_device-3");
  });

  it("uses the username as entered when no canonical user id is available", async () => {
    mockChallengeResponse({});

    const { signedIn } = authenticateWithPlaintextPassword({
      username: ALIAS_USERNAME,
      password: "secret",
      smsMfaCode: () => Promise.resolve("123456"),
    });
    await signedIn;

    expect(mockHandleAuthResponse).toHaveBeenCalledTimes(1);
    const callArgs = mockHandleAuthResponse.mock.calls[0][0];
    expect(callArgs.username).toBe(ALIAS_USERNAME);
    expect(callArgs.deviceHandler).toBeUndefined();
  });
});
