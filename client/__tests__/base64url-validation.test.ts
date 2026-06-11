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

import {
  bufferFromBase64,
  bufferFromBase64Url,
  bufferToBase64Url,
} from "../util.js";
import { prepareFido2SignIn } from "../fido2.js";
import { configure } from "../config.js";
import { Fido2ValidationError } from "../errors.js";
import { initiateAuth } from "../cognito-api.js";
import { retrieveDeviceKey } from "../storage.js";

// Mock dependencies
jest.mock("../config");
jest.mock("../cognito-api");
jest.mock("../storage");

const mockConfigure = configure as jest.MockedFunction<typeof configure>;
const mockInitiateAuth = initiateAuth as jest.MockedFunction<
  typeof initiateAuth
>;
const mockRetrieveDeviceKey = retrieveDeviceKey as jest.MockedFunction<
  typeof retrieveDeviceKey
>;

describe("bufferFromBase64Url defensive decoding", () => {
  it("returns an empty buffer for an empty string", () => {
    const result = bufferFromBase64Url("");
    expect(result).toBeInstanceOf(Uint8Array);
    expect(result.byteLength).toBe(0);
  });

  it("throws a descriptive error for characters outside the base64url alphabet", () => {
    expect(() => bufferFromBase64Url("!!!!")).toThrow(
      "Invalid base64 encoded string"
    );
  });

  it("rejects standard base64 characters that are not base64url", () => {
    expect(() => bufferFromBase64Url("a+b/")).toThrow(
      "Invalid base64 encoded string"
    );
  });

  it("decodes valid base64url input round-trip", () => {
    const bytes = new Uint8Array([72, 101, 108, 108, 111, 251, 255]);
    const encoded = bufferToBase64Url(bytes.buffer);
    expect(new Uint8Array(bufferFromBase64Url(encoded))).toEqual(bytes);
  });

  it("still decodes padded base64 input (bufferFromBase64)", () => {
    const result = bufferFromBase64("aGVsbG8=");
    expect(new Uint8Array(result)).toEqual(
      new Uint8Array([104, 101, 108, 108, 111]) // "hello"
    );
  });

  it("returns an empty buffer for an empty padded base64 string", () => {
    expect(bufferFromBase64("").byteLength).toBe(0);
  });
});

describe("FIDO2 options validation of empty strings", () => {
  const credentialGetter = jest.fn();

  beforeEach(() => {
    jest.clearAllMocks();
    mockConfigure.mockReturnValue({
      debug: undefined,
      fido2: {
        rp: { id: "example.com", name: "Example" },
        baseUrl: "https://example.com/fido2",
      },
    } as unknown as ReturnType<typeof configure>);
    mockRetrieveDeviceKey.mockResolvedValue(undefined);
  });

  function mockFido2Options(fido2options: Record<string, unknown>) {
    mockInitiateAuth.mockResolvedValueOnce({
      ChallengeParameters: {
        fido2options: JSON.stringify(fido2options),
      },
      Session: "session-token",
    } as unknown as Awaited<ReturnType<typeof initiateAuth>>);
  }

  it("rejects an empty challenge with Fido2ValidationError", async () => {
    mockFido2Options({ challenge: "" });
    await expect(
      prepareFido2SignIn({ username: "alice", credentialGetter })
    ).rejects.toThrow(Fido2ValidationError);
    expect(credentialGetter).not.toHaveBeenCalled();
  });

  it("rejects an empty credential id with Fido2ValidationError", async () => {
    mockFido2Options({
      challenge: "server-challenge",
      credentials: [{ id: "" }],
    });
    await expect(
      prepareFido2SignIn({ username: "alice", credentialGetter })
    ).rejects.toThrow(Fido2ValidationError);
    expect(credentialGetter).not.toHaveBeenCalled();
  });

  it("accepts valid options", async () => {
    mockFido2Options({
      challenge: "server-challenge",
      credentials: [{ id: "cred-1" }],
    });
    const parsedAssertion = {
      credentialIdB64: "cred-1",
      authenticatorDataB64: "auth-data",
      clientDataJSON_B64: "client-data",
      signatureB64: "signature",
      userHandleB64: null,
    };
    credentialGetter.mockResolvedValueOnce(parsedAssertion);

    const result = await prepareFido2SignIn({
      username: "alice",
      credentialGetter,
    });
    expect(result.credential).toEqual(parsedAssertion);
    expect(credentialGetter).toHaveBeenCalledWith(
      expect.objectContaining({ challenge: "server-challenge" })
    );
  });
});
