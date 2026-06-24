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
  Fido2CredentialRejectedError,
  isFido2CredentialRejectedError,
  Fido2AbortError,
} from "../errors.js";
import { configure } from "../config.js";
import { respondToAuthChallenge } from "../cognito-api.js";

jest.mock("../config");
jest.mock("../cognito-api");
jest.mock("../storage");

const mockConfigure = configure as jest.MockedFunction<typeof configure>;
const mockRespond = respondToAuthChallenge as jest.MockedFunction<
  typeof respondToAuthChallenge
>;

const STALE_CREDENTIAL_ID = "stale-credential-id-b64url";

function preparedBundle() {
  // A PreparedFido2SignIn: the assertion is already produced, so the failure
  // path runs through respondToAuthChallenge (the W5b discoverable scenario).
  return {
    username: "alice",
    session: "session-token",
    credential: {
      credentialIdB64: STALE_CREDENTIAL_ID,
      authenticatorDataB64: "auth-data",
      clientDataJSON_B64: "client-data",
      signatureB64: "signature",
      userHandleB64: null,
    },
    existingDeviceKey: undefined,
  };
}

function cognitoError(name: string, message: string): Error {
  const err = new Error(message);
  err.name = name;
  return err;
}

async function runSignInExpectingError(statusCb?: jest.Mock): Promise<unknown> {
  const { signedIn } = authenticateWithFido2({
    username: "alice",
    prepared: preparedBundle(),
    statusCb,
  });
  return signedIn.then(
    () => {
      throw new Error("sign-in unexpectedly succeeded");
    },
    (err) => err
  );
}

describe("Fido2CredentialRejectedError", () => {
  it("carries the reason, credentialId, code and cause", () => {
    const cause = new Error("origin");
    const error = new Fido2CredentialRejectedError("server says unknown", {
      reason: "unknown_credential",
      credentialIdB64: "cred-1",
      cause,
    });

    expect(error.name).toBe("Fido2CredentialRejectedError");
    expect(error.code).toBe("CREDENTIAL_REJECTED");
    expect(error.reason).toBe("unknown_credential");
    expect(error.credentialIdB64).toBe("cred-1");
    expect(error.cause).toBe(cause);
    expect(error.userMessage).toMatch(/no longer registered/i);
  });

  it("isFido2CredentialRejectedError narrows only its own instances", () => {
    const error = new Fido2CredentialRejectedError("x", {
      reason: "unknown_credential",
    });
    expect(isFido2CredentialRejectedError(error)).toBe(true);
    expect(isFido2CredentialRejectedError(new Error("nope"))).toBe(false);
    expect(
      isFido2CredentialRejectedError(
        new Fido2AbortError("aborted", "cancelled")
      )
    ).toBe(false);
  });
});

describe("authenticateWithFido2 unknown-credential re-tagging", () => {
  beforeEach(() => {
    jest.clearAllMocks();
    mockConfigure.mockReturnValue({
      debug: jest.fn(),
      fetch: jest.fn(),
      fido2: {
        rp: { id: "meow.com", name: "Meow" },
        baseUrl: "https://example.com/fido2",
        timeout: 45000,
        authenticatorSelection: { userVerification: "preferred" },
        extensions: {},
      },
    } as unknown as ReturnType<typeof configure>);
  });

  it("re-tags an explicit unknown_credential verdict, carrying the rejected credentialId", async () => {
    const original = cognitoError(
      "UserLambdaValidationException",
      '{"reason": "unknown_credential"}'
    );
    mockRespond.mockRejectedValueOnce(original);
    const statusCb = jest.fn();

    const error = await runSignInExpectingError(statusCb);

    expect(isFido2CredentialRejectedError(error)).toBe(true);
    const rejected = error as Fido2CredentialRejectedError;
    expect(rejected.reason).toBe("unknown_credential");
    expect(rejected.credentialIdB64).toBe(STALE_CREDENTIAL_ID);
    expect(rejected.cause).toBe(original);
    expect(statusCb).toHaveBeenCalledWith("FIDO2_SIGNIN_FAILED");
  });

  it("extracts the verdict even when Cognito wraps it with surrounding text and a trailing period", async () => {
    mockRespond.mockRejectedValueOnce(
      cognitoError(
        "UserLambdaValidationException",
        'VerifyAuthChallengeResponse failed with error {"reason": "unknown_credential"}.'
      )
    );

    const error = await runSignInExpectingError();

    expect(isFido2CredentialRejectedError(error)).toBe(true);
    expect((error as Fido2CredentialRejectedError).credentialIdB64).toBe(
      STALE_CREDENTIAL_ID
    );
  });

  it("does NOT re-tag a generic NotAuthorizedException (wrong PIN, expired session)", async () => {
    const original = cognitoError(
      "NotAuthorizedException",
      "Incorrect username or password."
    );
    mockRespond.mockRejectedValueOnce(original);

    const error = await runSignInExpectingError();

    expect(error).toBe(original);
    expect(isFido2CredentialRejectedError(error)).toBe(false);
  });

  it("does NOT re-tag a UserLambdaValidationException with a different reason", async () => {
    const original = cognitoError(
      "UserLambdaValidationException",
      '{"reason": "rate_limited"}'
    );
    mockRespond.mockRejectedValueOnce(original);

    const error = await runSignInExpectingError();

    expect(error).toBe(original);
    expect(isFido2CredentialRejectedError(error)).toBe(false);
  });

  it("does NOT re-tag a UserLambdaValidationException whose message is not JSON", async () => {
    const original = cognitoError(
      "UserLambdaValidationException",
      "Only FIDO2 authentication is supported"
    );
    mockRespond.mockRejectedValueOnce(original);

    const error = await runSignInExpectingError();

    expect(error).toBe(original);
    expect(isFido2CredentialRejectedError(error)).toBe(false);
  });

  it("does NOT re-tag a deliberate abort, and reverts to SIGNED_OUT", async () => {
    const original = cognitoError("AbortError", "The operation was aborted");
    mockRespond.mockRejectedValueOnce(original);
    const statusCb = jest.fn();

    const error = await runSignInExpectingError(statusCb);

    expect(error).toBe(original);
    expect(isFido2CredentialRejectedError(error)).toBe(false);
    expect(statusCb).toHaveBeenCalledWith("SIGNED_OUT");
    expect(statusCb).not.toHaveBeenCalledWith("FIDO2_SIGNIN_FAILED");
  });
});
