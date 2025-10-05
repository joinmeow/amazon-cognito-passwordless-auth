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
  getClientCapabilities,
  detectMediationCapabilities,
} from "../fido2.js";
import { TEST_CAPABILITIES } from "./__fixtures__/webauthn-credentials.js";
import {
  setupWebAuthnMock,
  setupNoBrowserSupportMock,
  createWebAuthnError,
} from "./__utils__/webauthn-mocks.js";

describe("WebAuthn Mediation Feature Detection", () => {
  let cleanup: (() => void) | null = null;

  afterEach(() => {
    if (cleanup) {
      cleanup();
      cleanup = null;
    }
  });

  describe("getClientCapabilities", () => {
    it("returns null when PublicKeyCredential is undefined", async () => {
      cleanup = setupNoBrowserSupportMock();

      const result = await getClientCapabilities();
      expect(result).toBeNull();
    });

    it("returns null when getClientCapabilities is not available", async () => {
      cleanup = setupWebAuthnMock({
        capabilities: undefined as any,
      });

      // Override to remove getClientCapabilities
      delete (global as any).PublicKeyCredential.getClientCapabilities;

      const result = await getClientCapabilities();
      expect(result).toBeNull();
    });

    it("returns known capabilities when getClientCapabilities is available", async () => {
      cleanup = setupWebAuthnMock({
        capabilities: TEST_CAPABILITIES,
      });

      const result = await getClientCapabilities();

      // Validate against known fixture values
      expect(result).toEqual(TEST_CAPABILITIES);
      expect(result?.conditionalGet).toBe(true);
      expect(result?.immediateGet).toBe(true);
      expect(result?.passkeyPlatformAuthenticator).toBe(true);
      expect(result?.userVerifyingPlatformAuthenticator).toBe(true);
      expect(result?.hybridTransport).toBe(true);
      expect(result?.signalAllAcceptedCredentials).toBe(true);
      expect(result?.signalCurrentUserDetails).toBe(true);

      expect(
        (global as any).PublicKeyCredential.getClientCapabilities
      ).toHaveBeenCalledTimes(1);
    });

    it("returns null and logs error on SecurityError", async () => {
      const consoleErrorSpy = jest.spyOn(console, "error").mockImplementation();

      const securityError = createWebAuthnError(
        "SecurityError",
        "Invalid domain"
      );

      (global as any).PublicKeyCredential = {
        getClientCapabilities: jest.fn().mockRejectedValue(securityError),
      };

      const result = await getClientCapabilities();
      expect(result).toBeNull();
      expect(consoleErrorSpy).toHaveBeenCalledWith(
        "Failed to get client capabilities:",
        securityError
      );

      consoleErrorSpy.mockRestore();
    });

    it("handles all spec-defined capabilities with known values", async () => {
      const fullCapabilities: Record<string, boolean | undefined> = {
        conditionalCreate: false,
        conditionalGet: true,
        hybridTransport: true,
        passkeyPlatformAuthenticator: true,
        userVerifyingPlatformAuthenticator: true,
        relatedOrigins: false,
        signalAllAcceptedCredentials: true,
        signalCurrentUserDetails: true,
        signalUnknownCredential: false,
        immediateGet: true,
        "extension:appid": false,
        "extension:credProps": true,
      };

      cleanup = setupWebAuthnMock({
        capabilities: fullCapabilities,
      });

      const result = await getClientCapabilities();

      // Validate exact fixture values
      expect(result).toEqual(fullCapabilities);
      expect(result?.conditionalCreate).toBe(false);
      expect(result?.conditionalGet).toBe(true);
      expect(result?.immediateGet).toBe(true);
      expect(result?.["extension:appid"]).toBe(false);
      expect(result?.["extension:credProps"]).toBe(true);
    });
  });

  describe("detectMediationCapabilities", () => {
    it("returns false for both when PublicKeyCredential is undefined", async () => {
      cleanup = setupNoBrowserSupportMock();

      const result = await detectMediationCapabilities();
      expect(result).toEqual({ conditional: false, immediate: false });
    });

    it("detects conditional mediation using legacy API", async () => {
      (global as any).PublicKeyCredential = {
        isConditionalMediationAvailable: jest.fn().mockResolvedValue(true),
        getClientCapabilities: jest.fn().mockResolvedValue({}),
      };

      const result = await detectMediationCapabilities();
      expect(result.conditional).toBe(true);
      expect(result.immediate).toBe(false);
      expect(
        (global as any).PublicKeyCredential.isConditionalMediationAvailable
      ).toHaveBeenCalledTimes(1);
    });

    it("detects immediate mediation from known capabilities", async () => {
      cleanup = setupWebAuthnMock({
        capabilities: {
          ...TEST_CAPABILITIES,
          immediateGet: true,
        },
      });

      // Remove legacy API to force getClientCapabilities path
      delete (global as any).PublicKeyCredential
        .isConditionalMediationAvailable;

      const result = await detectMediationCapabilities();
      expect(result.immediate).toBe(true);
    });

    it("uses conditionalGet as fallback for conditional mediation", async () => {
      cleanup = setupWebAuthnMock({
        capabilities: {
          conditionalGet: true,
          immediateGet: false,
        },
      });

      // Remove legacy API
      delete (global as any).PublicKeyCredential
        .isConditionalMediationAvailable;

      const result = await detectMediationCapabilities();
      expect(result.conditional).toBe(true);
      expect(result.immediate).toBe(false);
    });

    it("detects both capabilities from known fixture", async () => {
      cleanup = setupWebAuthnMock({
        capabilities: TEST_CAPABILITIES,
      });

      (global as any).PublicKeyCredential.isConditionalMediationAvailable = jest
        .fn()
        .mockResolvedValue(true);

      const result = await detectMediationCapabilities();
      expect(result).toEqual({ conditional: true, immediate: true });
    });

    it("handles errors gracefully from isConditionalMediationAvailable", async () => {
      (global as any).PublicKeyCredential = {
        isConditionalMediationAvailable: jest
          .fn()
          .mockRejectedValue(new Error("Test error")),
        getClientCapabilities: jest.fn().mockResolvedValue({}),
      };

      const result = await detectMediationCapabilities();
      expect(result.conditional).toBe(false);
      expect(result.immediate).toBe(false);
    });

    it("handles errors gracefully from getClientCapabilities", async () => {
      const consoleErrorSpy = jest.spyOn(console, "error").mockImplementation();

      (global as any).PublicKeyCredential = {
        getClientCapabilities: jest
          .fn()
          .mockRejectedValue(new Error("Test error")),
      };

      const result = await detectMediationCapabilities();
      expect(result.immediate).toBe(false);
      expect(result.conditional).toBe(false);

      consoleErrorSpy.mockRestore();
    });

    it("returns false when getClientCapabilities returns null", async () => {
      (global as any).PublicKeyCredential = {
        getClientCapabilities: jest.fn().mockResolvedValue(null),
      };

      const result = await detectMediationCapabilities();
      expect(result).toEqual({ conditional: false, immediate: false });
    });

    it("prefers legacy API for conditional over getClientCapabilities", async () => {
      (global as any).PublicKeyCredential = {
        isConditionalMediationAvailable: jest.fn().mockResolvedValue(true),
        getClientCapabilities: jest
          .fn()
          .mockResolvedValue({ conditionalGet: false, immediateGet: false }),
      };

      const result = await detectMediationCapabilities();
      expect(result.conditional).toBe(true);
      expect(result.immediate).toBe(false);
    });

    it("validates exact capability values from TEST_CAPABILITIES", async () => {
      cleanup = setupWebAuthnMock({
        capabilities: TEST_CAPABILITIES,
      });

      delete (global as any).PublicKeyCredential
        .isConditionalMediationAvailable;

      const result = await detectMediationCapabilities();

      // Validate against known fixture
      expect(result.conditional).toBe(TEST_CAPABILITIES.conditionalGet);
      expect(result.immediate).toBe(TEST_CAPABILITIES.immediateGet);
    });
  });
});
