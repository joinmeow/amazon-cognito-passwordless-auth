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

import { authenticateWithFido2 } from "../fido2.js";
import {
  Fido2AbortError,
  Fido2PasswordSelectedError,
  isFido2PasswordSelectedError,
} from "../errors.js";
import { configure } from "../config.js";
import { initiateAuth } from "../cognito-api.js";

jest.mock("../config");
jest.mock("../cognito-api");
jest.mock("../storage");

const mockConfigure = configure as jest.MockedFunction<typeof configure>;
const mockInitiateAuth = initiateAuth as jest.MockedFunction<
  typeof initiateAuth
>;

describe("isFido2PasswordSelectedError", () => {
  it("narrows only its own instances", () => {
    expect(
      isFido2PasswordSelectedError(
        new Fido2PasswordSelectedError("alice@example.com", "secret")
      )
    ).toBe(true);
    expect(isFido2PasswordSelectedError(new Fido2AbortError())).toBe(false);
    expect(isFido2PasswordSelectedError(new Error("nope"))).toBe(false);
  });
});

describe("authenticateWithFido2 with password: true", () => {
  beforeEach(() => {
    jest.clearAllMocks();
    mockConfigure.mockReturnValue({
      debug: jest.fn(),
      fetch: jest.fn(),
      fido2: {
        rp: { id: "example.com", name: "Example" },
        baseUrl: "https://example.com/fido2",
        extensions: {},
      },
    } as unknown as ReturnType<typeof configure>);
    mockInitiateAuth.mockResolvedValue({
      ChallengeName: "CUSTOM_CHALLENGE",
      ChallengeParameters: {
        fido2options: JSON.stringify({ challenge: "Y2hhbGxlbmdl" }),
      },
      Session: "session-token",
    } as unknown as Awaited<ReturnType<typeof initiateAuth>>);
  });

  it("passes password to the credential getter and reverts to SIGNED_OUT when a password is picked", async () => {
    const selected = new Fido2PasswordSelectedError(
      "alice@example.com",
      "secret"
    );
    const credentialGetter = jest.fn().mockRejectedValue(selected);
    const statusCb = jest.fn();

    const { signedIn } = authenticateWithFido2({
      username: "alice@example.com",
      mediation: "immediate",
      password: true,
      credentialGetter,
      statusCb,
    });

    await expect(signedIn).rejects.toBe(selected);
    expect(credentialGetter).toHaveBeenCalledWith(
      expect.objectContaining({ mediation: "immediate", password: true })
    );
    expect(statusCb).toHaveBeenLastCalledWith("SIGNED_OUT");
    expect(statusCb).not.toHaveBeenCalledWith("FIDO2_SIGNIN_FAILED");
  });
});
