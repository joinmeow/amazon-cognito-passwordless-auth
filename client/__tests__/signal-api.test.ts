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
import { bufferToBase64Url } from "../util.js";
import {
  signalAllAcceptedCredentials,
  signalUnknownCredential,
  signalCurrentUserDetails,
} from "../fido2.js";

jest.mock("../config");

const mockConfigure = configure as jest.MockedFunction<typeof configure>;

const RP_ID = "meow.com";
// The caller passes the relying party's user handle (the server's user.id); for
// Cognito with a raw-sub handle that is the user's sub.
const USER_HANDLE = "user-sub-abc";
// The Signal API userId must equal base64url(UTF-8 bytes of the user handle) —
// the exact value encodeUserHandle produces at registration.
const EXPECTED_USER_ID = bufferToBase64Url(
  new TextEncoder().encode(USER_HANDLE).buffer as ArrayBuffer
);

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
  });

  afterEach(() => {
    (
      global as unknown as { PublicKeyCredential: unknown }
    ).PublicKeyCredential = originalPublicKeyCredential;
  });

  it("signalAllAcceptedCredentials encodes the handle the same way registration does", async () => {
    armPublicKeyCredential(ALL_SUPPORTED);

    await signalAllAcceptedCredentials({
      allAcceptedCredentialIds: ["credA", "credB"],
      userId: USER_HANDLE,
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
      userId: USER_HANDLE,
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

    await signalAllAcceptedCredentials({
      allAcceptedCredentialIds: ["c"],
      userId: USER_HANDLE,
    });
    await signalUnknownCredential({ credentialId: "c" });
    await signalCurrentUserDetails({
      name: "n",
      displayName: "d",
      userId: USER_HANDLE,
    });

    expect(signalAllSpy).not.toHaveBeenCalled();
    expect(signalUnknownSpy).not.toHaveBeenCalled();
    expect(signalUserDetailsSpy).not.toHaveBeenCalled();
  });
});
