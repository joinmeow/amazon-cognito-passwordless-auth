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
import { processTokens } from "../common.js";
import { retrieveDeviceKey } from "../storage.js";
import { createDeviceSrpAuthHandler } from "../device.js";
import type { ConfigWithDefaults } from "../config.js";

jest.mock("../config");
jest.mock("../common");
jest.mock("../storage");
jest.mock("../device");
jest.mock("../cognito-security", () => ({
  CognitoSecurityProvider: {
    getInstance: jest.fn(() => ({
      getSecurityData: jest.fn().mockResolvedValue(undefined),
    })),
  },
}));

const mockConfigure = configure as jest.MockedFunction<typeof configure>;
const mockProcessTokens = processTokens as jest.MockedFunction<
  typeof processTokens
>;
const mockRetrieveDeviceKey = retrieveDeviceKey as jest.MockedFunction<
  typeof retrieveDeviceKey
>;
const mockCreateDeviceSrpAuthHandler =
  createDeviceSrpAuthHandler as jest.MockedFunction<
    typeof createDeviceSrpAuthHandler
  >;

describe("authenticateWithPlaintextPassword (USER_PASSWORD_AUTH) device key", () => {
  let mockFetch: jest.Mock;

  const getRequestBody = (call = 0) =>
    JSON.parse(
      (mockFetch.mock.calls[call] as [string, { body: string }])[1].body
    ) as {
      AuthFlow: string;
      AuthParameters: Record<string, string>;
    };

  beforeEach(() => {
    jest.clearAllMocks();

    mockFetch = jest.fn().mockResolvedValue({
      ok: true,
      json: () =>
        Promise.resolve({
          AuthenticationResult: {
            AccessToken: "mock-access-token",
            IdToken: "mock-id-token",
            RefreshToken: "mock-refresh-token",
            ExpiresIn: 3600,
            TokenType: "Bearer",
          },
        }),
    });

    mockConfigure.mockReturnValue({
      userPoolId: "eu-west-1_test",
      clientId: "test-client-id",
      cognitoIdpEndpoint: "eu-west-1",
      fetch: mockFetch,
      debug: undefined,
    } as unknown as ConfigWithDefaults);

    mockProcessTokens.mockImplementation((tokens) => Promise.resolve(tokens));
    mockRetrieveDeviceKey.mockResolvedValue(undefined);
    mockCreateDeviceSrpAuthHandler.mockResolvedValue({
      deviceKey: "unused",
      generateStep1: jest.fn(),
      generateStep2: jest.fn(),
    } as unknown as Awaited<ReturnType<typeof createDeviceSrpAuthHandler>>);
  });

  test("includes DEVICE_KEY in InitiateAuth AuthParameters when a device key is provided", async () => {
    const { signedIn } = authenticateWithPlaintextPassword({
      username: "test-user",
      password: "test-password",
      deviceKey: "explicit-device-key",
    });
    await signedIn;

    expect(mockFetch).toHaveBeenCalledTimes(1);
    const body = getRequestBody();
    expect(body.AuthFlow).toBe("USER_PASSWORD_AUTH");
    expect(body.AuthParameters).toMatchObject({
      USERNAME: "test-user",
      PASSWORD: "test-password",
      DEVICE_KEY: "explicit-device-key",
    });
  });

  test("includes remembered DEVICE_KEY from storage when none is provided", async () => {
    mockRetrieveDeviceKey.mockResolvedValue("remembered-device-key");

    const { signedIn } = authenticateWithPlaintextPassword({
      username: "test-user",
      password: "test-password",
    });
    await signedIn;

    expect(mockRetrieveDeviceKey).toHaveBeenCalledWith("test-user");
    const body = getRequestBody();
    expect(body.AuthParameters.DEVICE_KEY).toBe("remembered-device-key");
  });

  test("omits DEVICE_KEY when no device key is known", async () => {
    const { signedIn } = authenticateWithPlaintextPassword({
      username: "test-user",
      password: "test-password",
    });
    await signedIn;

    const body = getRequestBody();
    expect(body.AuthParameters).not.toHaveProperty("DEVICE_KEY");
  });
});
