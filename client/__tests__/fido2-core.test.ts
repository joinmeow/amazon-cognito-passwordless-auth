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

import { fido2getCredential } from "../fido2.js";
import { configure } from "../config.js";
import { Fido2CredentialError, Fido2ValidationError } from "../errors.js";
import {
  MOCK_ASSERTION_CREDENTIAL,
  EXPECTED_TRANSFORMED_CREDENTIAL,
  TEST_CHALLENGES,
  TEST_RP,
  base64UrlEncode,
} from "./__fixtures__/webauthn-credentials.js";
import {
  setupWebAuthnMock,
  createMockCredential,
  createWebAuthnError,
  assertTransformedCredentialMatches,
} from "./__utils__/webauthn-mocks.js";

// Mock dependencies
jest.mock("../config");
jest.mock("../cognito-api");
jest.mock("../storage");

const mockConfigure = configure as jest.MockedFunction<typeof configure>;

describe("FIDO2 Core Functionality", () => {
  let cleanup: (() => void) | null = null;

  beforeEach(() => {
    jest.clearAllMocks();
    if (cleanup) {
      cleanup();
      cleanup = null;
    }

    mockConfigure.mockReturnValue({
      debug: jest.fn(),
      fido2: {
        rp: { id: TEST_RP.id, name: TEST_RP.name },
        extensions: {},
      },
    } as any);
  });

  afterEach(() => {
    if (cleanup) {
      cleanup();
      cleanup = null;
    }
  });

  describe("fido2getCredential", () => {
    it("successfully retrieves a credential with known fixture values", async () => {
      cleanup = setupWebAuthnMock({
        credential: MOCK_ASSERTION_CREDENTIAL,
      });

      const result = await fido2getCredential({
        challenge: TEST_CHALLENGES.basic,
        relyingPartyId: TEST_RP.id,
      });

      // Validate against known fixture values
      assertTransformedCredentialMatches(
        result,
        EXPECTED_TRANSFORMED_CREDENTIAL
      );
      expect(result.credentialIdB64).toBe(
        EXPECTED_TRANSFORMED_CREDENTIAL.credentialIdB64
      );
      expect(result.authenticatorDataB64).toBe(
        EXPECTED_TRANSFORMED_CREDENTIAL.authenticatorDataB64
      );
      expect(result.clientDataJSON_B64).toBe(
        EXPECTED_TRANSFORMED_CREDENTIAL.clientDataJSON_B64
      );
      expect(result.signatureB64).toBe(
        EXPECTED_TRANSFORMED_CREDENTIAL.signatureB64
      );
      expect(result.userHandleB64).toBe(
        EXPECTED_TRANSFORMED_CREDENTIAL.userHandleB64
      );
    });

    it("handles credential without userHandle", async () => {
      const credentialWithoutUserHandle = createMockCredential({
        response: {
          ...MOCK_ASSERTION_CREDENTIAL.response,
          userHandle: null,
        } as AuthenticatorAssertionResponse,
      });

      cleanup = setupWebAuthnMock({
        credential: credentialWithoutUserHandle,
      });

      const result = await fido2getCredential({
        challenge: TEST_CHALLENGES.basic,
      });

      expect(result.userHandleB64).toBeNull();
      // Other fields should still match
      expect(result.credentialIdB64).toBe(
        EXPECTED_TRANSFORMED_CREDENTIAL.credentialIdB64
      );
      expect(result.authenticatorDataB64).toBe(
        EXPECTED_TRANSFORMED_CREDENTIAL.authenticatorDataB64
      );
    });

    it("passes credentials to allowCredentials with known values", async () => {
      const getSpy = jest.fn().mockResolvedValue(MOCK_ASSERTION_CREDENTIAL);

      cleanup = setupWebAuthnMock({
        customCredentials: {
          get: getSpy,
          create: jest.fn(),
        } as any,
      });

      const knownCredentialId1 = base64UrlEncode(
        new Uint8Array([0x01, 0x02, 0x03]).buffer
      );
      const knownCredentialId2 = base64UrlEncode(
        new Uint8Array([0x04, 0x05, 0x06]).buffer
      );

      await fido2getCredential({
        challenge: TEST_CHALLENGES.basic,
        credentials: [
          { id: knownCredentialId1, transports: ["internal", "hybrid"] },
          { id: knownCredentialId2, transports: ["usb"] },
        ],
      });

      // Verify getSpy was called
      expect(getSpy).toHaveBeenCalledTimes(1);

      const callArgs = getSpy.mock.calls[0][0];
      expect(callArgs.publicKey.allowCredentials).toHaveLength(2);
      expect(callArgs.publicKey.allowCredentials[0]).toMatchObject({
        type: "public-key",
        transports: ["internal", "hybrid"],
      });
      expect(callArgs.publicKey.allowCredentials[1]).toMatchObject({
        type: "public-key",
        transports: ["usb"],
      });
      // Verify ids are ArrayBuffer-like (have byteLength)
      expect(callArgs.publicKey.allowCredentials[0].id).toHaveProperty(
        "byteLength"
      );
      expect(callArgs.publicKey.allowCredentials[1].id).toHaveProperty(
        "byteLength"
      );
    });

    it("throws error when no credential returned", async () => {
      cleanup = setupWebAuthnMock({
        credential: null,
      });

      await expect(
        fido2getCredential({
          challenge: TEST_CHALLENGES.basic,
        })
      ).rejects.toThrow(Fido2CredentialError);
    });

    it("throws validation error for invalid credential response", async () => {
      const invalidCredential = {
        id: "test-id",
        type: "public-key",
        // Missing response fields
      } as any;

      cleanup = setupWebAuthnMock({
        credential: invalidCredential,
      });

      await expect(
        fido2getCredential({
          challenge: TEST_CHALLENGES.basic,
        })
      ).rejects.toThrow(Fido2ValidationError);
    });

    it("applies timeout and userVerification parameters with known values", async () => {
      const getSpy = jest.fn().mockResolvedValue(MOCK_ASSERTION_CREDENTIAL);

      cleanup = setupWebAuthnMock({
        customCredentials: {
          get: getSpy,
          create: jest.fn(),
        } as any,
      });

      const knownTimeout = 60000;
      const knownUserVerification = "required";

      await fido2getCredential({
        challenge: TEST_CHALLENGES.basic,
        timeout: knownTimeout,
        userVerification: knownUserVerification,
      });

      expect(getSpy).toHaveBeenCalledWith(
        expect.objectContaining({
          publicKey: expect.objectContaining({
            timeout: knownTimeout,
            userVerification: knownUserVerification,
          }),
        })
      );
    });

    it("uses config extensions when available with known values", async () => {
      const knownExtensions = {
        credProps: true,
        appid: "https://example.com/appid.json",
      };

      mockConfigure.mockReturnValue({
        debug: jest.fn(),
        fido2: {
          rp: { id: TEST_RP.id, name: TEST_RP.name },
          extensions: knownExtensions,
        },
      } as any);

      const getSpy = jest.fn().mockResolvedValue(MOCK_ASSERTION_CREDENTIAL);

      cleanup = setupWebAuthnMock({
        customCredentials: {
          get: getSpy,
          create: jest.fn(),
        } as any,
      });

      await fido2getCredential({
        challenge: TEST_CHALLENGES.basic,
      });

      expect(getSpy).toHaveBeenCalledWith(
        expect.objectContaining({
          publicKey: expect.objectContaining({
            extensions: knownExtensions,
          }),
        })
      );
    });

    it("handles special characters in challenge", async () => {
      cleanup = setupWebAuthnMock({
        credential: MOCK_ASSERTION_CREDENTIAL,
      });

      const result = await fido2getCredential({
        challenge: TEST_CHALLENGES.special,
      });

      expect(result.credentialIdB64).toBe(
        EXPECTED_TRANSFORMED_CREDENTIAL.credentialIdB64
      );
    });
  });

  describe("fido2CreateCredential", () => {
    // Note: Full integration tests for credential creation are complex
    // as they require mocking multiple API calls. These are covered by
    // the existing fido2-errors.test.ts file.
  });

  describe("Error Handling", () => {
    it("converts known DOMException to custom error with specific message", async () => {
      const domError = createWebAuthnError("NotAllowedError", "User cancelled");

      cleanup = setupWebAuthnMock({
        getError: domError,
      });

      await expect(
        fido2getCredential({
          challenge: TEST_CHALLENGES.basic,
        })
      ).rejects.toThrow("Operation not allowed");
    });

    it("handles AbortError with specific message", async () => {
      const abortError = createWebAuthnError("AbortError", "Operation aborted");

      cleanup = setupWebAuthnMock({
        getError: abortError,
      });

      await expect(
        fido2getCredential({
          challenge: TEST_CHALLENGES.basic,
        })
      ).rejects.toThrow("WebAuthn operation was aborted");
    });

    it("passes through non-DOMException errors with exact message", async () => {
      const networkError = new Error("Network error");

      cleanup = setupWebAuthnMock({
        getError: networkError,
      });

      await expect(
        fido2getCredential({
          challenge: TEST_CHALLENGES.basic,
        })
      ).rejects.toThrow("Network error");
    });
  });
});
