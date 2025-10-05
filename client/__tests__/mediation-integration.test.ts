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
import { Fido2ConfigError } from "../errors.js";
import {
  MOCK_ASSERTION_CREDENTIAL,
  TEST_CHALLENGES,
  TEST_RP,
} from "./__fixtures__/webauthn-credentials.js";
import {
  setupWebAuthnMock,
  setupNoConditionalMediationMock,
  setupNoBrowserSupportMock,
  createMockAbortController,
} from "./__utils__/webauthn-mocks.js";

// Mock dependencies
jest.mock("../config");
const mockConfigure = configure as jest.MockedFunction<typeof configure>;

describe("Mediation Integration Tests", () => {
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

  describe("Conditional Mediation", () => {
    it("logs warning when conditional mediation cannot be verified", async () => {
      const debugSpy = jest.fn();
      mockConfigure.mockReturnValue({
        debug: debugSpy,
        fido2: {
          rp: { id: TEST_RP.id, name: TEST_RP.name },
        },
      } as any);

      cleanup = setupNoConditionalMediationMock();

      await fido2getCredential({
        challenge: TEST_CHALLENGES.basic,
        mediation: "conditional",
      });

      expect(debugSpy).toHaveBeenCalledWith(
        expect.stringContaining("Cannot verify conditional mediation support")
      );
    });

    it("allows conditional mediation when supported with known fixtures", async () => {
      const getSpy = jest.fn().mockResolvedValue(MOCK_ASSERTION_CREDENTIAL);

      (global as any).PublicKeyCredential = {
        isConditionalMediationAvailable: jest.fn().mockResolvedValue(true),
      };

      // Use Object.defineProperty for jsdom compatibility
      Object.defineProperty((global as any).navigator, "credentials", {
        value: {
          get: getSpy,
        },
        configurable: true,
        writable: true,
      });

      const knownTimeout = 60000;

      const result = await fido2getCredential({
        challenge: TEST_CHALLENGES.basic,
        mediation: "conditional",
        userVerification: "required", // Should be overridden
        timeout: knownTimeout, // Should be removed
      });

      expect(result).toBeDefined();
      expect(getSpy).toHaveBeenCalledWith(
        expect.objectContaining({
          publicKey: expect.objectContaining({
            userVerification: "preferred", // Overridden per spec
            timeout: undefined, // Removed per spec
          }),
          mediation: "conditional",
        })
      );
    });

    it("logs warnings when overriding parameters for conditional mediation", async () => {
      const debugSpy = jest.fn();
      mockConfigure.mockReturnValue({
        debug: debugSpy,
        fido2: {
          rp: { id: TEST_RP.id, name: TEST_RP.name },
        },
      } as any);

      const getSpy = jest.fn().mockResolvedValue(MOCK_ASSERTION_CREDENTIAL);

      (global as any).PublicKeyCredential = {
        isConditionalMediationAvailable: jest.fn().mockResolvedValue(true),
      };

      // Use Object.defineProperty for jsdom compatibility
      Object.defineProperty((global as any).navigator, "credentials", {
        value: {
          get: getSpy,
        },
        configurable: true,
        writable: true,
      });

      const knownTimeout = 30000;

      await fido2getCredential({
        challenge: TEST_CHALLENGES.basic,
        mediation: "conditional",
        userVerification: "required",
        timeout: knownTimeout,
      });

      expect(debugSpy).toHaveBeenCalledWith(
        expect.stringContaining(
          'WebAuthn spec requires userVerification="preferred"'
        )
      );
      expect(debugSpy).toHaveBeenCalledWith(
        expect.stringContaining("WebAuthn spec recommends removing timeout")
      );
    });
  });

  describe("Immediate Mediation", () => {
    it("validates PublicKeyCredential availability for immediate mediation", async () => {
      cleanup = setupNoBrowserSupportMock();

      await expect(
        fido2getCredential({
          challenge: TEST_CHALLENGES.basic,
          mediation: "immediate",
        })
      ).rejects.toThrow(Fido2ConfigError);
    });

    it("uses immediate mediation without parameter overrides with known values", async () => {
      const getSpy = jest.fn().mockResolvedValue(MOCK_ASSERTION_CREDENTIAL);

      cleanup = setupWebAuthnMock({
        customCredentials: {
          get: getSpy,
          create: jest.fn(),
        } as any,
      });

      const knownTimeout = 30000;
      const knownUserVerification = "required";

      await fido2getCredential({
        challenge: TEST_CHALLENGES.basic,
        mediation: "immediate",
        userVerification: knownUserVerification,
        timeout: knownTimeout,
      });

      expect(getSpy).toHaveBeenCalledWith(
        expect.objectContaining({
          publicKey: expect.objectContaining({
            userVerification: knownUserVerification, // Not overridden for immediate
            timeout: knownTimeout, // Not removed for immediate
          }),
          mediation: "immediate",
        })
      );
    });

    it("logs debug message for immediate mediation", async () => {
      const debugSpy = jest.fn();
      mockConfigure.mockReturnValue({
        debug: debugSpy,
        fido2: {
          rp: { id: TEST_RP.id, name: TEST_RP.name },
        },
      } as any);

      cleanup = setupWebAuthnMock({
        credential: MOCK_ASSERTION_CREDENTIAL,
      });

      await fido2getCredential({
        challenge: TEST_CHALLENGES.basic,
        mediation: "immediate",
      });

      expect(debugSpy).toHaveBeenCalledWith(
        "Using immediate mediation - will fail fast with NotAllowedError if no local credentials"
      );
    });
  });

  describe("Abort Signal Integration", () => {
    it("passes known abort signal to navigator.credentials.get", async () => {
      const getSpy = jest.fn().mockResolvedValue(MOCK_ASSERTION_CREDENTIAL);

      cleanup = setupWebAuthnMock({
        customCredentials: {
          get: getSpy,
          create: jest.fn(),
        } as any,
      });

      const { controller } = createMockAbortController();

      await fido2getCredential({
        challenge: TEST_CHALLENGES.basic,
        mediation: "conditional",
        signal: controller.signal,
      });

      expect(getSpy).toHaveBeenCalledWith(
        expect.objectContaining({
          signal: controller.signal,
        })
      );
    });

    it("handles abort signal cancellation", async () => {
      const { controller, abort } = createMockAbortController();

      const getSpy = jest.fn().mockImplementation(async ({ signal }) => {
        // Simulate abort during request
        abort();
        if (signal?.aborted) {
          throw new DOMException("The operation was aborted", "AbortError");
        }
        return MOCK_ASSERTION_CREDENTIAL;
      });

      cleanup = setupWebAuthnMock({
        customCredentials: {
          get: getSpy,
          create: jest.fn(),
        } as any,
      });

      await expect(
        fido2getCredential({
          challenge: TEST_CHALLENGES.basic,
          signal: controller.signal,
        })
      ).rejects.toThrow("aborted");
    });
  });

  describe("No Mediation (Default)", () => {
    it("works without mediation parameter with known values", async () => {
      const getSpy = jest.fn().mockResolvedValue(MOCK_ASSERTION_CREDENTIAL);

      cleanup = setupWebAuthnMock({
        customCredentials: {
          get: getSpy,
          create: jest.fn(),
        } as any,
      });

      const knownTimeout = 30000;
      const knownUserVerification = "required";

      await fido2getCredential({
        challenge: TEST_CHALLENGES.basic,
        userVerification: knownUserVerification,
        timeout: knownTimeout,
      });

      // Should use parameters as-is without overrides
      expect(getSpy).toHaveBeenCalledWith(
        expect.objectContaining({
          publicKey: expect.objectContaining({
            userVerification: knownUserVerification,
            timeout: knownTimeout,
          }),
          mediation: undefined,
        })
      );
    });
  });
});
