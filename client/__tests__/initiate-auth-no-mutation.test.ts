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

import { configure } from "../config.js";
import type { MinimalFetch } from "../config.js";
import { initiateAuth } from "../cognito-api.js";

describe("initiateAuth does not mutate the caller's authParameters", () => {
  let fetchMock: jest.Mock;

  beforeEach(() => {
    fetchMock = jest.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ AuthenticationResult: {} }),
    });
    configure({
      clientId: "test-client",
      cognitoIdpEndpoint: "us-east-1",
      fetch: fetchMock as unknown as MinimalFetch,
    });
  });

  const sentDeviceKey = () => {
    const body = JSON.parse(fetchMock.mock.calls[0][1].body as string) as {
      AuthParameters: Record<string, string>;
    };
    return body.AuthParameters.DEVICE_KEY;
  };

  it("sends DEVICE_KEY in the request without adding it to the caller's object", async () => {
    const authParameters: Record<string, string> = {
      USERNAME: "alice",
      PASSWORD: "secret",
    };

    await initiateAuth({
      authflow: "USER_PASSWORD_AUTH",
      authParameters,
      deviceKey: "us-east-1_device",
    });

    // The request carried the device key ...
    expect(sentDeviceKey()).toBe("us-east-1_device");
    // ... but the caller's object was NOT mutated
    expect(authParameters).toEqual({ USERNAME: "alice", PASSWORD: "secret" });
    expect("DEVICE_KEY" in authParameters).toBe(false);
  });

  it("reuses the same authParameters object across two calls without leaking DEVICE_KEY", async () => {
    const authParameters: Record<string, string> = {
      USERNAME: "alice",
      PASSWORD: "secret",
    };

    // First attempt WITH a device key
    await initiateAuth({
      authflow: "USER_PASSWORD_AUTH",
      authParameters,
      deviceKey: "us-east-1_device",
    });
    // Second attempt WITHOUT a device key, reusing the same object: it must
    // not still carry the first attempt's DEVICE_KEY (the previous mutation
    // bug left it stuck on the object).
    await initiateAuth({
      authflow: "USER_PASSWORD_AUTH",
      authParameters,
    });

    const secondBody = JSON.parse(
      fetchMock.mock.calls[1][1].body as string
    ) as { AuthParameters: Record<string, string> };
    expect("DEVICE_KEY" in secondBody.AuthParameters).toBe(false);
  });
});
