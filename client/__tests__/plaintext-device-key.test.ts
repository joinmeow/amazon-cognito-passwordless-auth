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

import { webcrypto } from "crypto";
import { authenticateWithPlaintextPassword } from "../plaintext.js";
import { configure } from "../config.js";
import type { MinimalCrypto } from "../config.js";
import {
  setRememberedDevice,
  getRememberedDevice,
  storeDeviceKey,
} from "../storage.js";
import { createDeviceSrpAuthHandler } from "../device.js";
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

const CLIENT_ID = "test-client";
const CANONICAL_USER_ID = "canonical-user-sub";
const ALIAS_USERNAME = "alias@example.com";
const LAST_AUTH_USER_KEY = `CognitoIdentityServiceProvider.${CLIENT_ID}.LastAuthUser`;

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

let memoryStorage: ReturnType<typeof createMemoryStorage>;

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

function buildAuthenticatedResponse() {
  // Access token whose payload carries the canonical username claim
  const accessToken = `${btoa(JSON.stringify({ alg: "none" }))}.${btoa(
    JSON.stringify({
      username: CANONICAL_USER_ID,
      exp: Math.floor(Date.now() / 1000) + 3600,
    })
  )}.signature`;
  return {
    AuthenticationResult: {
      AccessToken: accessToken,
      IdToken: "test-id-token",
      RefreshToken: "test-refresh-token",
      ExpiresIn: 3600,
      TokenType: "Bearer",
    },
    ChallengeParameters: {},
  } as unknown as Awaited<ReturnType<typeof initiateAuth>>;
}

function mockAuthenticatedResponse() {
  mockInitiateAuth.mockResolvedValue(buildAuthenticatedResponse());
}

function deviceNotFoundError() {
  // Shape thrown by throwIfNot2xx / assertIsNotErrorResponse for Cognito's
  // ResourceNotFoundException when a device key is no longer known
  const err = new Error("Device does not exist.");
  err.name = "ResourceNotFoundException";
  return err;
}

/** deviceKey argument of the n-th initiateAuth call */
function initiateAuthDeviceKey(call: number) {
  return mockInitiateAuth.mock.calls[call][0].deviceKey;
}

beforeEach(() => {
  jest.clearAllMocks();
  memoryStorage = createMemoryStorage();
  configure({
    clientId: CLIENT_ID,
    userPoolId: "us-east-1_testpool",
    storage: memoryStorage,
    // Real WebCrypto so the device SRP handler can compute SRP_A
    crypto: webcrypto as unknown as MinimalCrypto,
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

describe("authenticateWithPlaintextPassword (USER_PASSWORD_AUTH) device key", () => {
  test("includes DEVICE_KEY in initiateAuth when a device key is provided", async () => {
    mockAuthenticatedResponse();

    const { signedIn } = authenticateWithPlaintextPassword({
      username: "test-user",
      password: "test-password",
      deviceKey: "explicit-device-key",
    });
    await signedIn;

    expect(mockInitiateAuth).toHaveBeenCalledTimes(1);
    expect(mockInitiateAuth).toHaveBeenCalledWith(
      expect.objectContaining({
        authflow: "USER_PASSWORD_AUTH",
        authParameters: expect.objectContaining({
          USERNAME: "test-user",
          PASSWORD: "test-password",
        }) as unknown,
        deviceKey: "explicit-device-key",
      })
    );
  });

  test("includes remembered DEVICE_KEY from storage when none is provided", async () => {
    await setRememberedDevice("test-user", {
      deviceKey: "remembered-device-key",
      groupKey: "group-key",
      password: "device-password",
      remembered: true,
    });
    mockAuthenticatedResponse();

    const { signedIn } = authenticateWithPlaintextPassword({
      username: "test-user",
      password: "test-password",
    });
    await signedIn;

    expect(mockInitiateAuth).toHaveBeenCalledTimes(1);
    expect(initiateAuthDeviceKey(0)).toBe("remembered-device-key");
  });

  test("does not send another user's (LastAuthUser) device key when signing in with a different identifier", async () => {
    // On a shared browser, LastAuthUser may belong to someone else entirely.
    // Their device key must never be attached to this user's credentials —
    // Cognito would reject it, and the stale-key recovery would then wipe
    // the OTHER user's remembered device.
    memoryStorage.setItem(LAST_AUTH_USER_KEY, CANONICAL_USER_ID);
    await setRememberedDevice(CANONICAL_USER_ID, {
      deviceKey: "other-users-device-key",
      groupKey: "group-key",
      password: "device-password",
      remembered: true,
    });
    mockAuthenticatedResponse();

    const { signedIn } = authenticateWithPlaintextPassword({
      username: ALIAS_USERNAME,
      password: "secret",
    });
    await signedIn;

    expect(mockInitiateAuth).toHaveBeenCalledTimes(1);
    expect(initiateAuthDeviceKey(0)).toBeUndefined();
    // The other user's record is untouched
    expect(await getRememberedDevice(CANONICAL_USER_ID)).toMatchObject({
      deviceKey: "other-users-device-key",
    });
  });

  test("does not send a device key from a placeholder record without device password", async () => {
    // storeDeviceKey creates placeholder records with an empty password.
    // Sending such a key would make Cognito issue a DEVICE_SRP_AUTH
    // challenge this client cannot answer — and that failure is not a
    // ResourceNotFoundException, so the stale-key retry would not recover.
    await storeDeviceKey("test-user", "shadow-device-key");

    mockAuthenticatedResponse();

    const { signedIn } = authenticateWithPlaintextPassword({
      username: "test-user",
      password: "test-password",
    });
    await signedIn;

    expect(mockInitiateAuth).toHaveBeenCalledTimes(1);
    expect(initiateAuthDeviceKey(0)).toBeUndefined();
  });

  test("copies the canonical device record to the alias key after a successful alias sign-in, then sends it next time", async () => {
    // Confirmed devices are stored under the CANONICAL user id (#71). The
    // first alias sign-in cannot safely use it pre-auth — but once the
    // sign-in succeeds (attribution verified), the record is copied to the
    // alias key so subsequent alias sign-ins send the device key.
    await setRememberedDevice(CANONICAL_USER_ID, {
      deviceKey: "canonical-device-key",
      groupKey: "group-key",
      password: "device-password",
      remembered: true,
    });
    mockAuthenticatedResponse();

    // First alias sign-in: no key sent, record copied on success
    await authenticateWithPlaintextPassword({
      username: ALIAS_USERNAME,
      password: "secret",
    }).signedIn;
    expect(initiateAuthDeviceKey(0)).toBeUndefined();
    expect(await getRememberedDevice(ALIAS_USERNAME)).toMatchObject({
      deviceKey: "canonical-device-key",
    });

    // Second alias sign-in: the copied record is found pre-auth
    await authenticateWithPlaintextPassword({
      username: ALIAS_USERNAME,
      password: "secret",
    }).signedIn;
    expect(mockInitiateAuth).toHaveBeenCalledTimes(2);
    expect(initiateAuthDeviceKey(1)).toBe("canonical-device-key");
  });

  test("omits DEVICE_KEY when no device key is known", async () => {
    mockAuthenticatedResponse();

    const { signedIn } = authenticateWithPlaintextPassword({
      username: "test-user",
      password: "test-password",
    });
    await signedIn;

    expect(mockInitiateAuth).toHaveBeenCalledTimes(1);
    expect(initiateAuthDeviceKey(0)).toBeUndefined();
  });

  test("valid device key happy path: exactly one initiateAuth call, record kept", async () => {
    await setRememberedDevice("test-user", {
      deviceKey: "valid-device-key",
      groupKey: "group-key",
      password: "device-password",
      remembered: true,
    });
    mockAuthenticatedResponse();

    const { signedIn } = authenticateWithPlaintextPassword({
      username: "test-user",
      password: "test-password",
    });
    const tokens = await signedIn;

    expect(mockInitiateAuth).toHaveBeenCalledTimes(1);
    expect(tokens.accessToken).toBe("mock-access-token");
    expect(await getRememberedDevice("test-user")).toMatchObject({
      deviceKey: "valid-device-key",
    });
  });
});

describe("stale device key fallback", () => {
  test("clears the stale record and retries once without DEVICE_KEY when Cognito rejects it", async () => {
    await setRememberedDevice("test-user", {
      deviceKey: "stale-device-key",
      groupKey: "group-key",
      password: "device-password",
      remembered: true,
    });
    mockInitiateAuth
      .mockRejectedValueOnce(deviceNotFoundError())
      .mockResolvedValueOnce(buildAuthenticatedResponse());

    const { signedIn } = authenticateWithPlaintextPassword({
      username: "test-user",
      password: "test-password",
    });
    const tokens = await signedIn;

    // Sign-in succeeded where it used to hard-fail
    expect(tokens.accessToken).toBe("mock-access-token");
    expect(mockInitiateAuth).toHaveBeenCalledTimes(2);
    expect(initiateAuthDeviceKey(0)).toBe("stale-device-key");
    expect(initiateAuthDeviceKey(1)).toBeUndefined();
    // The stale record was cleared, so it won't be sent again
    expect(await getRememberedDevice("test-user")).toBeUndefined();
  });

  test("clears only the alias-keyed record the stale key came from, never another user's record", async () => {
    // A previously-copied alias record goes stale: it is cleared and the
    // sign-in retried — but the canonical record (potentially refreshed by
    // another flow) is not touched, because we only clear the exact record
    // the rejected key was read from
    await setRememberedDevice(ALIAS_USERNAME, {
      deviceKey: "stale-device-key",
      groupKey: "group-key",
      password: "device-password",
      remembered: true,
    });
    await setRememberedDevice(CANONICAL_USER_ID, {
      deviceKey: "fresh-canonical-key",
      groupKey: "group-key",
      password: "device-password",
      remembered: true,
    });
    mockInitiateAuth
      .mockRejectedValueOnce(deviceNotFoundError())
      .mockResolvedValueOnce(buildAuthenticatedResponse());

    const { signedIn } = authenticateWithPlaintextPassword({
      username: ALIAS_USERNAME,
      password: "secret",
    });
    await signedIn;

    expect(mockInitiateAuth).toHaveBeenCalledTimes(2);
    expect(initiateAuthDeviceKey(0)).toBe("stale-device-key");
    // The canonical record survives; the alias record was re-copied from it
    // after the successful retry (fresh key for next time)
    expect(await getRememberedDevice(CANONICAL_USER_ID)).toMatchObject({
      deviceKey: "fresh-canonical-key",
    });
    expect(await getRememberedDevice(ALIAS_USERNAME)).toMatchObject({
      deviceKey: "fresh-canonical-key",
    });
  });

  test("retries without DEVICE_KEY when the device challenge path rejects the device", async () => {
    await setRememberedDevice("test-user", {
      deviceKey: "stale-device-key",
      groupKey: "group-key",
      password: "device-password",
      remembered: true,
    });
    mockAuthenticatedResponse();
    // First full attempt fails during the (device) challenge handling
    mockHandleAuthResponse.mockRejectedValueOnce(deviceNotFoundError());

    const { signedIn } = authenticateWithPlaintextPassword({
      username: "test-user",
      password: "test-password",
    });
    const tokens = await signedIn;

    expect(tokens.accessToken).toBe("mock-access-token");
    expect(mockInitiateAuth).toHaveBeenCalledTimes(2);
    expect(initiateAuthDeviceKey(1)).toBeUndefined();
    expect(await getRememberedDevice("test-user")).toBeUndefined();
  });

  test("clears the matching stored record when an explicitly passed device key is stale", async () => {
    // The caller passed the key explicitly, but the same key also lives in
    // the entered user's stored record: a stale rejection must clear that
    // record (and never rebuild a device handler around the rejected key),
    // or the retry could fail again with no second recovery
    await setRememberedDevice("test-user", {
      deviceKey: "stale-explicit-key",
      groupKey: "group-key",
      password: "device-password",
      remembered: true,
    });
    mockInitiateAuth
      .mockRejectedValueOnce(deviceNotFoundError())
      .mockResolvedValueOnce(buildAuthenticatedResponse());

    const { signedIn } = authenticateWithPlaintextPassword({
      username: "test-user",
      password: "test-password",
      deviceKey: "stale-explicit-key",
    });
    const tokens = await signedIn;

    expect(tokens.accessToken).toBe("mock-access-token");
    expect(mockInitiateAuth).toHaveBeenCalledTimes(2);
    expect(initiateAuthDeviceKey(1)).toBeUndefined();
    expect(await getRememberedDevice("test-user")).toBeUndefined();
    // The retry must not rebuild a device handler around the rejected key
    expect(
      mockHandleAuthResponse.mock.calls[0][0].deviceHandler
    ).toBeUndefined();
  });

  test("clears a stale canonical record after the retry so the alias copy is not resurrected", async () => {
    // Alias copy AND canonical record both hold the same stale key (e.g.
    // the device was forgotten via forgetDevice on another browser). The
    // retry clears the alias record it sent from; the canonical record
    // holding the same rejected key must be cleared too — otherwise the
    // post-auth alias-copy would resurrect the stale key on every sign-in
    await setRememberedDevice(ALIAS_USERNAME, {
      deviceKey: "stale-device-key",
      groupKey: "group-key",
      password: "device-password",
      remembered: true,
    });
    await setRememberedDevice(CANONICAL_USER_ID, {
      deviceKey: "stale-device-key",
      groupKey: "group-key",
      password: "device-password",
      remembered: true,
    });
    mockInitiateAuth
      .mockRejectedValueOnce(deviceNotFoundError())
      .mockResolvedValue(buildAuthenticatedResponse());

    await authenticateWithPlaintextPassword({
      username: ALIAS_USERNAME,
      password: "secret",
    }).signedIn;

    expect(mockInitiateAuth).toHaveBeenCalledTimes(2);
    expect(await getRememberedDevice(ALIAS_USERNAME)).toBeUndefined();
    expect(await getRememberedDevice(CANONICAL_USER_ID)).toBeUndefined();

    // The next alias sign-in has nothing stale left to send
    await authenticateWithPlaintextPassword({
      username: ALIAS_USERNAME,
      password: "secret",
    }).signedIn;
    expect(mockInitiateAuth).toHaveBeenCalledTimes(3);
    expect(initiateAuthDeviceKey(2)).toBeUndefined();
  });

  test("does not retry when no device key was sent", async () => {
    mockInitiateAuth.mockRejectedValue(deviceNotFoundError());

    const { signedIn } = authenticateWithPlaintextPassword({
      username: "test-user",
      password: "test-password",
    });
    await expect(signedIn).rejects.toThrow("Device does not exist.");

    expect(mockInitiateAuth).toHaveBeenCalledTimes(1);
  });

  test("does not retry on non-device errors", async () => {
    await setRememberedDevice("test-user", {
      deviceKey: "some-device-key",
      groupKey: "group-key",
      password: "device-password",
      remembered: true,
    });
    const err = new Error("Incorrect username or password.");
    err.name = "NotAuthorizedException";
    mockInitiateAuth.mockRejectedValue(err);

    const { signedIn } = authenticateWithPlaintextPassword({
      username: "test-user",
      password: "test-password",
    });
    await expect(signedIn).rejects.toThrow("Incorrect username or password.");

    expect(mockInitiateAuth).toHaveBeenCalledTimes(1);
    // Record untouched: the key was not the problem
    expect(await getRememberedDevice("test-user")).toMatchObject({
      deviceKey: "some-device-key",
    });
  });
});

describe("plaintext flow device record lookup", () => {
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

    // The legacy record is also found pre-auth and sent with initiateAuth
    expect(initiateAuthDeviceKey(0)).toBe("us-east-1_device-2");
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

describe("device SRP handler and shadow records", () => {
  it("does not build a handler from a placeholder record without device password", async () => {
    // storeDeviceKey creates a "shadow" record with empty password/groupKey
    await storeDeviceKey("test-user", "shadow-device-key");

    const handler = await createDeviceSrpAuthHandler(
      "test-user",
      "shadow-device-key"
    );

    expect(handler).toBeUndefined();
  });

  it("falls through a shadow record to a full record under another username key", async () => {
    // Shadow record under the canonical id (e.g. created by storeDeviceKey
    // during token refresh), full legacy record under the alias
    memoryStorage.setItem(LAST_AUTH_USER_KEY, CANONICAL_USER_ID);
    await storeDeviceKey(CANONICAL_USER_ID, "us-east-1_device-9");
    await setRememberedDevice(ALIAS_USERNAME, {
      deviceKey: "us-east-1_device-9",
      groupKey: "group-key-9",
      password: "device-password-9",
      remembered: true,
    });
    mockChallengeResponse();

    const { signedIn } = authenticateWithPlaintextPassword({
      username: ALIAS_USERNAME,
      password: "secret",
      smsMfaCode: () => Promise.resolve("123456"),
    });
    await signedIn;

    const callArgs = mockHandleAuthResponse.mock.calls[0][0];
    // The shadow record under the canonical id is skipped, the full record
    // under the alias provides the SRP handler
    expect(callArgs.deviceHandler?.deviceKey).toBe("us-east-1_device-9");
    const step1 = await callArgs.deviceHandler?.generateStep1();
    expect(step1?.srpAHex).toBeTruthy();
  });
});
