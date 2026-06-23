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
import { retrieveTokens } from "../storage.js";
import { bufferToBase64Url } from "../util.js";
import {
  signalAllAcceptedCredentials,
  signalUnknownCredential,
  signalCurrentUserDetails,
} from "../fido2.js";

jest.mock("../config");
jest.mock("../storage");

const mockConfigure = configure as jest.MockedFunction<typeof configure>;
const mockRetrieveTokens = retrieveTokens as jest.MockedFunction<
  typeof retrieveTokens
>;

const RP_ID = "meow.com";
const SUB = "user-sub-abc";
// The Signal API userId must equal base64url(UTF-8 bytes of the raw Cognito sub),
// i.e. the exact handle encodeUserHandle produces at registration.
const EXPECTED_USER_ID = bufferToBase64Url(
  new TextEncoder().encode(SUB).buffer as ArrayBuffer
);

function base64urlSegment(obj: object): string {
  return bufferToBase64Url(
    new TextEncoder().encode(JSON.stringify(obj)).buffer as ArrayBuffer
  );
}

function makeIdToken(sub: string): string {
  return `${base64urlSegment({ alg: "RS256" })}.${base64urlSegment({ sub })}.sig`;
}

const ALL_SUPPORTED = {
  signalAllAcceptedCredentials: true,
  signalUnknownCredential: true,
  signalCurrentUserDetails: true,
};

describe("WebAuthn Signal API wrappers", () => {
  let signalAllSpy: jest.Mock;
  let signalUnknownSpy: jest.Mock;
  let signalUserDetailsSpy: jest.Mock;
  let originalPublicKeyCredential: unknown;

  function armPublicKeyCredential(capabilities: Record<string, boolean>) {
    signalAllSpy = jest.fn().mockResolvedValue(undefined);
    signalUnknownSpy = jest.fn().mockResolvedValue(undefined);
    signalUserDetailsSpy = jest.fn().mockResolvedValue(undefined);
    (
      global as unknown as { PublicKeyCredential: unknown }
    ).PublicKeyCredential = {
      getClientCapabilities: jest.fn().mockResolvedValue(capabilities),
      signalAllAcceptedCredentials: signalAllSpy,
      signalUnknownCredential: signalUnknownSpy,
      signalCurrentUserDetails: signalUserDetailsSpy,
    };
  }

  beforeEach(() => {
    jest.clearAllMocks();
    originalPublicKeyCredential = (
      global as unknown as { PublicKeyCredential: unknown }
    ).PublicKeyCredential;
    mockConfigure.mockReturnValue({
      debug: jest.fn(),
      fetch: jest.fn(),
      location: { hostname: "localhost", href: "https://localhost/" },
      fido2: { rp: { id: RP_ID } },
    } as unknown as ReturnType<typeof configure>);
    mockRetrieveTokens.mockResolvedValue({
      idToken: makeIdToken(SUB),
    } as Awaited<ReturnType<typeof retrieveTokens>>);
  });

  afterEach(() => {
    (
      global as unknown as { PublicKeyCredential: unknown }
    ).PublicKeyCredential = originalPublicKeyCredential;
  });

  it("signalAllAcceptedCredentials sends the encoded handle, rpId and credential ids", async () => {
    armPublicKeyCredential(ALL_SUPPORTED);

    await signalAllAcceptedCredentials({
      allAcceptedCredentialIds: ["credA", "credB"],
    });

    expect(signalAllSpy).toHaveBeenCalledWith({
      rpId: RP_ID,
      userId: EXPECTED_USER_ID,
      allAcceptedCredentialIds: ["credA", "credB"],
    });
  });

  it("signalUnknownCredential sends rpId and credentialId without a user handle", async () => {
    armPublicKeyCredential(ALL_SUPPORTED);

    await signalUnknownCredential({ credentialId: "credX" });

    expect(signalUnknownSpy).toHaveBeenCalledWith({
      rpId: RP_ID,
      credentialId: "credX",
    });
  });

  it("signalCurrentUserDetails sends the encoded handle, name and display name", async () => {
    armPublicKeyCredential(ALL_SUPPORTED);

    await signalCurrentUserDetails({
      name: "user@meow.com",
      displayName: "User",
    });

    expect(signalUserDetailsSpy).toHaveBeenCalledWith({
      rpId: RP_ID,
      userId: EXPECTED_USER_ID,
      name: "user@meow.com",
      displayName: "User",
    });
  });

  it("honours an explicit rpId override", async () => {
    armPublicKeyCredential(ALL_SUPPORTED);

    await signalUnknownCredential({ credentialId: "credX", rpId: "other.com" });

    expect(signalUnknownSpy).toHaveBeenCalledWith({
      rpId: "other.com",
      credentialId: "credX",
    });
  });

  it("no-ops when the browser does not support the capability", async () => {
    armPublicKeyCredential({
      signalAllAcceptedCredentials: false,
      signalUnknownCredential: false,
      signalCurrentUserDetails: false,
    });

    await signalAllAcceptedCredentials({ allAcceptedCredentialIds: ["c"] });
    await signalUnknownCredential({ credentialId: "c" });
    await signalCurrentUserDetails({ name: "n", displayName: "d" });

    expect(signalAllSpy).not.toHaveBeenCalled();
    expect(signalUnknownSpy).not.toHaveBeenCalled();
    expect(signalUserDetailsSpy).not.toHaveBeenCalled();
  });

  it("no-ops the user-scoped signals when no one is signed in", async () => {
    armPublicKeyCredential(ALL_SUPPORTED);
    mockRetrieveTokens.mockResolvedValue(undefined);

    await signalAllAcceptedCredentials({ allAcceptedCredentialIds: ["c"] });
    await signalCurrentUserDetails({ name: "n", displayName: "d" });

    expect(signalAllSpy).not.toHaveBeenCalled();
    expect(signalUserDetailsSpy).not.toHaveBeenCalled();
  });
});
