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
import { Fido2AbortError, Fido2ConfigError } from "../errors.js";
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
  waitFor,
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
        mediation: "immediate",
        signal: controller.signal,
      });

      expect(getSpy).toHaveBeenCalledWith(
        expect.objectContaining({
          signal: controller.signal,
        })
      );
    });

    it("chains the caller's abort signal for conditional requests", async () => {
      // For conditional requests an internal AbortController is used (so a
      // subsequent modal request can cancel the autofill request), chained
      // to the caller's signal
      const getSpy = jest.fn().mockImplementation(
        ({ signal }: { signal?: AbortSignal }) =>
          new Promise((_resolve, reject) => {
            signal?.addEventListener("abort", () =>
              reject(
                new DOMException("The operation was aborted", "AbortError")
              )
            );
          })
      );

      cleanup = setupWebAuthnMock({
        customCredentials: {
          get: getSpy,
          create: jest.fn(),
        } as any,
      });

      const { controller } = createMockAbortController();

      const conditional = fido2getCredential({
        challenge: TEST_CHALLENGES.basic,
        mediation: "conditional",
        signal: controller.signal,
      }).catch((err: unknown) => err);
      await waitFor(() => getSpy.mock.calls.length === 1);

      controller.abort();

      const err = await conditional;
      expect(err).toBeInstanceOf(Fido2AbortError);
      // A caller-initiated abort is a real cancellation, not a takeover
      expect((err as Fido2AbortError).superseded).toBe(false);
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

  describe("Concurrent Conditional and Modal Requests", () => {
    /** A credentials.get() mock that hangs until its abort signal fires */
    const hangingGet = ({ signal }: { signal?: AbortSignal }) =>
      new Promise((_resolve, reject) => {
        signal?.addEventListener("abort", () =>
          reject(new DOMException("The operation was aborted", "AbortError"))
        );
      });

    it("aborts a pending conditional (autofill) request when a modal request starts", async () => {
      const getSpy = jest
        .fn()
        .mockImplementationOnce(hangingGet)
        .mockResolvedValueOnce(MOCK_ASSERTION_CREDENTIAL);

      cleanup = setupWebAuthnMock({
        customCredentials: {
          get: getSpy,
          create: jest.fn(),
        } as any,
      });

      // Conditional (autofill) request kicked off at page load
      const conditional = fido2getCredential({
        challenge: TEST_CHALLENGES.basic,
        mediation: "conditional",
      }).catch((err: unknown) => err);
      await waitFor(() => getSpy.mock.calls.length === 1);

      // User clicks "sign in with passkey" → modal request
      const modalResult = await fido2getCredential({
        challenge: TEST_CHALLENGES.basic,
      });

      // The pending conditional request was aborted, the modal one proceeded
      const conditionalErr = await conditional;
      expect(conditionalErr).toBeInstanceOf(Fido2AbortError);
      // The abort was a takeover by the modal request, not a cancellation
      // by the caller's own signal
      expect((conditionalErr as Fido2AbortError).superseded).toBe(true);
      expect(modalResult).toBeDefined();
      expect(getSpy).toHaveBeenCalledTimes(2);
      const conditionalSignal = getSpy.mock.calls[0][0].signal as AbortSignal;
      expect(conditionalSignal.aborted).toBe(true);
    });

    it("aborts a pending conditional request when a new conditional request starts", async () => {
      const getSpy = jest
        .fn()
        .mockImplementationOnce(hangingGet)
        .mockResolvedValueOnce(MOCK_ASSERTION_CREDENTIAL);

      cleanup = setupWebAuthnMock({
        customCredentials: {
          get: getSpy,
          create: jest.fn(),
        } as any,
      });

      const first = fido2getCredential({
        challenge: TEST_CHALLENGES.basic,
        mediation: "conditional",
      }).catch((err: unknown) => err);
      await waitFor(() => getSpy.mock.calls.length === 1);

      const second = await fido2getCredential({
        challenge: TEST_CHALLENGES.basic,
        mediation: "conditional",
      });

      const firstErr = await first;
      expect(firstErr).toBeInstanceOf(Fido2AbortError);
      expect((firstErr as Fido2AbortError).superseded).toBe(true);
      expect(second).toBeDefined();
      expect(getSpy).toHaveBeenCalledTimes(2);
    });

    it("does not abort anything when the conditional request already resolved", async () => {
      const getSpy = jest.fn().mockResolvedValue(MOCK_ASSERTION_CREDENTIAL);

      cleanup = setupWebAuthnMock({
        customCredentials: {
          get: getSpy,
          create: jest.fn(),
        } as any,
      });

      // Conditional request resolves normally → tracker must be cleared
      const conditionalResult = await fido2getCredential({
        challenge: TEST_CHALLENGES.basic,
        mediation: "conditional",
      });
      expect(conditionalResult).toBeDefined();

      const modalResult = await fido2getCredential({
        challenge: TEST_CHALLENGES.basic,
      });
      expect(modalResult).toBeDefined();

      expect(getSpy).toHaveBeenCalledTimes(2);
      const conditionalSignal = getSpy.mock.calls[0][0].signal as AbortSignal;
      expect(conditionalSignal.aborted).toBe(false);
    });

    it("leaves sequential modal requests unaffected", async () => {
      const getSpy = jest.fn().mockResolvedValue(MOCK_ASSERTION_CREDENTIAL);

      cleanup = setupWebAuthnMock({
        customCredentials: {
          get: getSpy,
          create: jest.fn(),
        } as any,
      });

      const first = await fido2getCredential({
        challenge: TEST_CHALLENGES.basic,
      });
      const second = await fido2getCredential({
        challenge: TEST_CHALLENGES.basic,
      });

      expect(first).toBeDefined();
      expect(second).toBeDefined();
      expect(getSpy).toHaveBeenCalledTimes(2);
      // No internal signal is injected for modal requests
      expect(getSpy.mock.calls[0][0].signal).toBeUndefined();
      expect(getSpy.mock.calls[1][0].signal).toBeUndefined();
    });

    it("serializes concurrent modal requests so credentials.get() calls don't overlap", async () => {
      // The browser rejects overlapping credentials.get() requests, so a
      // second modal request must wait until the first one settles
      let inFlight = 0;
      let maxInFlight = 0;
      const resolvers: ((value: unknown) => void)[] = [];
      const getSpy = jest.fn().mockImplementation(() => {
        inFlight++;
        maxInFlight = Math.max(maxInFlight, inFlight);
        return new Promise((resolve) => {
          resolvers.push((value) => {
            inFlight--;
            resolve(value);
          });
        });
      });

      cleanup = setupWebAuthnMock({
        customCredentials: {
          get: getSpy,
          create: jest.fn(),
        } as any,
      });

      const first = fido2getCredential({
        challenge: TEST_CHALLENGES.basic,
      });
      const second = fido2getCredential({
        challenge: TEST_CHALLENGES.basic,
      });
      await waitFor(() => getSpy.mock.calls.length === 1);

      // The second request is queued until the first one settles
      await new Promise((resolve) => setTimeout(resolve, 50));
      expect(getSpy).toHaveBeenCalledTimes(1);

      resolvers[0](MOCK_ASSERTION_CREDENTIAL);
      await waitFor(() => getSpy.mock.calls.length === 2);
      resolvers[1](MOCK_ASSERTION_CREDENTIAL);

      expect(await first).toBeDefined();
      expect(await second).toBeDefined();
      expect(maxInFlight).toBe(1);
    });

    it("queues a conditional request behind an in-flight modal request without aborting it", async () => {
      // A modal request shows browser UI the user is interacting with - a
      // new conditional (autofill) request must not abort it, but it also
      // must not overlap with it: it waits for the modal request to settle
      let resolveModal!: (value: unknown) => void;
      const getSpy = jest
        .fn()
        .mockImplementationOnce(
          () => new Promise((resolve) => (resolveModal = resolve))
        )
        .mockImplementationOnce(hangingGet)
        .mockResolvedValue(MOCK_ASSERTION_CREDENTIAL);

      cleanup = setupWebAuthnMock({
        customCredentials: {
          get: getSpy,
          create: jest.fn(),
        } as any,
      });

      const modal = fido2getCredential({
        challenge: TEST_CHALLENGES.basic,
      });
      await waitFor(() => getSpy.mock.calls.length === 1);

      const conditional = fido2getCredential({
        challenge: TEST_CHALLENGES.basic,
        mediation: "conditional",
      }).catch((err: unknown) => err);

      // The conditional request waits for the modal request to settle
      await new Promise((resolve) => setTimeout(resolve, 50));
      expect(getSpy).toHaveBeenCalledTimes(1);

      resolveModal(MOCK_ASSERTION_CREDENTIAL);
      expect(await modal).toBeDefined();

      // Now the conditional request is issued
      await waitFor(() => getSpy.mock.calls.length === 2);
      const conditionalSignal = getSpy.mock.calls[1][0].signal as AbortSignal;
      expect(conditionalSignal.aborted).toBe(false);

      // Clean up: take over the pending conditional request
      const takeoverResult = await fido2getCredential({
        challenge: TEST_CHALLENGES.basic,
      });
      expect(takeoverResult).toBeDefined();
      expect(await conditional).toBeInstanceOf(Fido2AbortError);
    });

    it("aborts a pending conditional request once when multiple modal requests start concurrently", async () => {
      const getSpy = jest
        .fn()
        .mockImplementationOnce(hangingGet)
        .mockResolvedValue(MOCK_ASSERTION_CREDENTIAL);

      cleanup = setupWebAuthnMock({
        customCredentials: {
          get: getSpy,
          create: jest.fn(),
        } as any,
      });

      const conditional = fido2getCredential({
        challenge: TEST_CHALLENGES.basic,
        mediation: "conditional",
      }).catch((err: unknown) => err);
      await waitFor(() => getSpy.mock.calls.length === 1);

      // Two modal requests racing (e.g. double-click on the sign-in button)
      const [firstModal, secondModal] = await Promise.all([
        fido2getCredential({ challenge: TEST_CHALLENGES.basic }),
        fido2getCredential({ challenge: TEST_CHALLENGES.basic }),
      ]);

      expect(await conditional).toBeInstanceOf(Fido2AbortError);
      expect(firstModal).toBeDefined();
      expect(secondModal).toBeDefined();
      // Conditional + two (serialized) modal requests
      expect(getSpy).toHaveBeenCalledTimes(3);
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
