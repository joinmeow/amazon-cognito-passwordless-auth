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

import { Blob as NodeBlob } from "buffer";
import { webcrypto } from "crypto";
import { TextEncoder as NodeTextEncoder } from "util";

// jsdom does not provide TextEncoder
if (typeof globalThis.TextEncoder === "undefined") {
  globalThis.TextEncoder = NodeTextEncoder as typeof globalThis.TextEncoder;
}
// jsdom's Blob lacks arrayBuffer(); use Node's implementation
if (typeof Blob.prototype.arrayBuffer !== "function") {
  globalThis.Blob = NodeBlob as unknown as typeof Blob;
}

import { authenticateWithSRP } from "../srp.js";
import { handleDeviceConfirmation } from "../device.js";
import { configure } from "../config.js";
import type { MinimalCrypto } from "../config.js";
import { setRememberedDevice, getRememberedDevice } from "../storage.js";
import type { TokensFromSignIn } from "../model.js";
import * as cognitoApi from "../cognito-api.js";
import { processTokens } from "../common.js";

// cognito-api.ts and device.ts import each other; a jest.mock factory with
// requireActual re-enters that cycle mid-construction and splits the module
// identity (device.ts ends up calling a different confirmDevice instance
// than the test configured). jest.spyOn on the namespace avoids this: the
// CommonJS transform resolves the property at call time, so every importer
// sees the spy.
jest.mock("../common.js", () => ({
  processTokens: jest.fn(),
}));

let mockInitiateAuth: jest.MockedFunction<typeof cognitoApi.initiateAuth>;
let mockRespondToAuthChallenge: jest.MockedFunction<
  typeof cognitoApi.respondToAuthChallenge
>;
let mockHandleAuthResponse: jest.MockedFunction<
  typeof cognitoApi.handleAuthResponse
>;
let mockConfirmDevice: jest.MockedFunction<typeof cognitoApi.confirmDevice>;
const mockProcessTokens = processTokens as jest.MockedFunction<
  typeof processTokens
>;

const USER_ID_FOR_SRP = "canonical-user-sub";

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

function passwordVerifierChallenge() {
  return {
    ChallengeName: "PASSWORD_VERIFIER",
    ChallengeParameters: {
      SALT: "aabbccddeeff112233",
      SRP_B: "1234abcd9876ef01",
      SECRET_BLOCK: "c2VjcmV0LWJsb2Nr",
      USER_ID_FOR_SRP,
      USERNAME: USER_ID_FOR_SRP,
    },
    Session: "test-session",
  } as unknown as Awaited<ReturnType<typeof cognitoApi.initiateAuth>>;
}

function authenticatedResult() {
  return {
    AuthenticationResult: {
      AccessToken: "test-access-token",
      IdToken: "test-id-token",
      RefreshToken: "test-refresh-token",
      ExpiresIn: 3600,
      TokenType: "Bearer",
    },
    ChallengeParameters: {},
  } as unknown as Awaited<ReturnType<typeof cognitoApi.respondToAuthChallenge>>;
}

function deviceNotFoundError() {
  const err = new Error("Device does not exist.");
  err.name = "ResourceNotFoundException";
  return err;
}

/** challengeResponses of the n-th respondToAuthChallenge call */
function challengeResponses(call: number) {
  return mockRespondToAuthChallenge.mock.calls[call][0].challengeResponses;
}

beforeEach(() => {
  jest.restoreAllMocks();
  mockProcessTokens.mockClear();
  mockInitiateAuth = jest.spyOn(
    cognitoApi,
    "initiateAuth"
  ) as unknown as jest.MockedFunction<typeof cognitoApi.initiateAuth>;
  mockRespondToAuthChallenge = jest.spyOn(
    cognitoApi,
    "respondToAuthChallenge"
  ) as unknown as jest.MockedFunction<
    typeof cognitoApi.respondToAuthChallenge
  >;
  mockHandleAuthResponse = jest.spyOn(
    cognitoApi,
    "handleAuthResponse"
  ) as unknown as jest.MockedFunction<typeof cognitoApi.handleAuthResponse>;
  mockConfirmDevice = jest.spyOn(
    cognitoApi,
    "confirmDevice"
  ) as unknown as jest.MockedFunction<typeof cognitoApi.confirmDevice>;
  configure({
    clientId: "test-client",
    userPoolId: "us-east-1_testpool",
    storage: createMemoryStorage(),
    // Real WebCrypto: the SRP signature is computed for real
    crypto: webcrypto as unknown as MinimalCrypto,
  });
  mockInitiateAuth.mockResolvedValue(passwordVerifierChallenge());
  mockRespondToAuthChallenge.mockResolvedValue(authenticatedResult());
  mockHandleAuthResponse.mockImplementation(({ username }) =>
    Promise.resolve({
      accessToken: "test-access-token",
      idToken: "test-id-token",
      refreshToken: "test-refresh-token",
      expireAt: new Date(Date.now() + 3600 * 1000),
      username,
      deviceKey: undefined,
      newDeviceMetadata: undefined,
    })
  );
  mockProcessTokens.mockImplementation((tokens) => Promise.resolve(tokens));
});

describe("authenticateWithSRP device key handling", () => {
  test("sends DEVICE_KEY from a complete remembered record", async () => {
    await setRememberedDevice(USER_ID_FOR_SRP, {
      deviceKey: "remembered-device-key",
      groupKey: "group-key",
      password: "device-password",
      remembered: true,
    });

    await authenticateWithSRP({
      username: "alice@example.com",
      password: "secret",
    }).signedIn;

    expect(mockRespondToAuthChallenge).toHaveBeenCalledTimes(1);
    expect(challengeResponses(0).DEVICE_KEY).toBe("remembered-device-key");
  });

  test("does not send a device key from a placeholder record without device password", async () => {
    // Placeholder records (created by storeDeviceKey without a confirmed
    // device) have no device password: sending their key would make
    // Cognito issue a DEVICE_SRP_AUTH challenge this client cannot answer
    await setRememberedDevice(USER_ID_FOR_SRP, {
      deviceKey: "shadow-device-key",
      groupKey: "",
      password: "",
      remembered: false,
    });

    await authenticateWithSRP({
      username: "alice@example.com",
      password: "secret",
    }).signedIn;

    expect(mockRespondToAuthChallenge).toHaveBeenCalledTimes(1);
    expect(challengeResponses(0).DEVICE_KEY).toBeUndefined();
  });

  test("clears the stale record and retries the challenge once without DEVICE_KEY", async () => {
    // The device was forgotten server-side (e.g. forgetDevice from another
    // browser) while the local record survived. Previously this PERMANENTLY
    // bricked SRP sign-in: every attempt sent the stale key, Cognito
    // rejected it, and the record was never cleared.
    await setRememberedDevice(USER_ID_FOR_SRP, {
      deviceKey: "stale-device-key",
      groupKey: "group-key",
      password: "device-password",
      remembered: true,
    });
    mockRespondToAuthChallenge
      .mockRejectedValueOnce(deviceNotFoundError())
      .mockResolvedValueOnce(authenticatedResult());

    const tokens = await authenticateWithSRP({
      username: "alice@example.com",
      password: "secret",
    }).signedIn;

    // Sign-in succeeded where it used to hard-fail, with a single
    // initiateAuth (the SRP proof is unchanged, so the same signature and
    // session are re-sent — mirroring amazon-cognito-identity-js)
    expect(tokens.accessToken).toBe("test-access-token");
    expect(mockInitiateAuth).toHaveBeenCalledTimes(1);
    expect(mockRespondToAuthChallenge).toHaveBeenCalledTimes(2);
    expect(challengeResponses(0).DEVICE_KEY).toBe("stale-device-key");
    expect(challengeResponses(1).DEVICE_KEY).toBeUndefined();
    expect(challengeResponses(1).PASSWORD_CLAIM_SIGNATURE).toBe(
      challengeResponses(0).PASSWORD_CLAIM_SIGNATURE
    );
    expect(mockRespondToAuthChallenge.mock.calls[1][0].session).toBe(
      mockRespondToAuthChallenge.mock.calls[0][0].session
    );
    // The stale record was cleared, so it won't be sent again
    expect(await getRememberedDevice(USER_ID_FOR_SRP)).toBeUndefined();
    // The retry must not hand a handler built around the rejected key to
    // the challenge loop
    expect(
      mockHandleAuthResponse.mock.calls[0][0].deviceHandler
    ).toBeUndefined();
  });

  test("does not retry on non-device errors", async () => {
    await setRememberedDevice(USER_ID_FOR_SRP, {
      deviceKey: "some-device-key",
      groupKey: "group-key",
      password: "device-password",
      remembered: true,
    });
    const err = new Error("Incorrect username or password.");
    err.name = "NotAuthorizedException";
    mockRespondToAuthChallenge.mockRejectedValue(err);

    await expect(
      authenticateWithSRP({
        username: "alice@example.com",
        password: "secret",
      }).signedIn
    ).rejects.toThrow("Incorrect username or password.");

    expect(mockRespondToAuthChallenge).toHaveBeenCalledTimes(1);
    // Record untouched: the key was not the problem
    expect(await getRememberedDevice(USER_ID_FOR_SRP)).toMatchObject({
      deviceKey: "some-device-key",
    });
  });
});

describe("handleDeviceConfirmation failure", () => {
  test("drops the unconfirmed device key: not set on tokens, nothing persisted", async () => {
    // Regression: a failed ConfirmDevice used to set tokens.deviceKey
    // anyway, which storeTokens then persisted as a placeholder record
    // (no device password) — the planting mechanism for keys that get
    // replayed on future sign-ins but can never complete device auth
    mockConfirmDevice.mockRejectedValue(new Error("network error"));

    const tokens: TokensFromSignIn = {
      accessToken: "test-access-token",
      idToken: "test-id-token",
      refreshToken: "test-refresh-token",
      expireAt: new Date(Date.now() + 3600 * 1000),
      username: USER_ID_FOR_SRP,
      newDeviceMetadata: {
        deviceKey: "us-east-1_fresh-device",
        deviceGroupKey: "fresh-group-key",
      },
    };

    const result = await handleDeviceConfirmation(tokens);

    expect(result.deviceKey).toBeUndefined();
    expect(await getRememberedDevice(USER_ID_FOR_SRP)).toBeUndefined();
  });

  test("persists the full record when confirmation succeeds", async () => {
    mockConfirmDevice.mockResolvedValue({
      UserConfirmationNecessary: false,
    } as unknown as Awaited<ReturnType<typeof cognitoApi.confirmDevice>>);

    const tokens: TokensFromSignIn = {
      accessToken: "test-access-token",
      idToken: "test-id-token",
      refreshToken: "test-refresh-token",
      expireAt: new Date(Date.now() + 3600 * 1000),
      username: USER_ID_FOR_SRP,
      newDeviceMetadata: {
        deviceKey: "us-east-1_fresh-device",
        deviceGroupKey: "fresh-group-key",
      },
    };

    const result = await handleDeviceConfirmation(tokens);

    expect(result.deviceKey).toBe("us-east-1_fresh-device");
    const record = await getRememberedDevice(USER_ID_FOR_SRP);
    expect(record).toMatchObject({ deviceKey: "us-east-1_fresh-device" });
    expect(record?.password).toBeTruthy();
  });
});
