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
  fido2getCredential,
  prepareFido2SignIn,
  authenticateWithFido2,
  COGNITO_AUTH_SESSION_RENEWAL_INTERVAL_MS,
} from "../fido2.js";
import { configure } from "../config.js";
import {
  Fido2AbortError,
  Fido2CredentialError,
  Fido2ValidationError,
} from "../errors.js";
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
import { initiateAuth, respondToAuthChallenge } from "../cognito-api.js";
import { retrieveDeviceKey } from "../storage.js";
import { bufferToBase64Url } from "../util.js";
import { TextDecoder as NodeTextDecoder } from "util";

if (typeof globalThis.TextDecoder === "undefined") {
  (
    globalThis as unknown as { TextDecoder: typeof NodeTextDecoder }
  ).TextDecoder = NodeTextDecoder;
}

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
const mockRespondToAuthChallenge =
  respondToAuthChallenge as jest.MockedFunction<typeof respondToAuthChallenge>;

describe("FIDO2 Core Functionality", () => {
  let cleanup: (() => void) | null = null;
  let baseConfig: any;

  beforeEach(() => {
    jest.clearAllMocks();
    if (cleanup) {
      cleanup();
      cleanup = null;
    }

    baseConfig = {
      debug: jest.fn(),
      fetch: jest.fn(),
      fido2: {
        rp: { id: TEST_RP.id, name: TEST_RP.name },
        baseUrl: "https://example.com/fido2",
        timeout: 45000,
        authenticatorSelection: { userVerification: "preferred" },
        extensions: {},
      },
    } as any;

    mockConfigure.mockReturnValue(baseConfig);
    mockRetrieveDeviceKey.mockResolvedValue(undefined);
    mockInitiateAuth.mockReset();
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

  describe("prepareFido2SignIn", () => {
    const toArrayBuffer = (buf: Buffer) =>
      buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength);

    it("prepares authentication with explicit username and merges credentials", async () => {
      const parsedAssertion = {
        credentialIdB64: "cred-1",
        authenticatorDataB64: "auth-data",
        clientDataJSON_B64: "client-data",
        signatureB64: "signature",
        userHandleB64: null,
      };
      const credentialGetter = jest.fn().mockResolvedValue(parsedAssertion);

      mockRetrieveDeviceKey.mockResolvedValueOnce("device-key-123");
      mockInitiateAuth.mockResolvedValueOnce({
        ChallengeParameters: {
          fido2options: JSON.stringify({
            challenge: "server-challenge",
            relyingPartyId: "server-rp",
            timeout: 60000,
            userVerification: "discouraged",
            credentials: [{ id: "cred-existing" }],
          }),
        },
        Session: "session-token",
      } as any);

      const result = await prepareFido2SignIn({
        username: "alice",
        credentials: [{ id: "cred-existing" }, { id: "cred-new" }],
        mediation: "immediate",
        credentialGetter,
      });

      expect(mockRetrieveDeviceKey).toHaveBeenCalledWith("alice");
      expect(mockInitiateAuth).toHaveBeenCalledWith(
        expect.objectContaining({
          authflow: "CUSTOM_AUTH",
          authParameters: {
            USERNAME: "alice",
            DEVICE_KEY: "device-key-123",
          },
        })
      );

      const credentialGetterArgs = credentialGetter.mock.calls[0][0];
      expect(credentialGetterArgs.challenge).toBe("server-challenge");
      expect(credentialGetterArgs.relyingPartyId).toBe(TEST_RP.id);
      expect(credentialGetterArgs.timeout).toBe(baseConfig.fido2.timeout);
      expect(credentialGetterArgs.userVerification).toBe(
        baseConfig.fido2.authenticatorSelection.userVerification
      );
      expect(credentialGetterArgs.mediation).toBe("immediate");
      const allowCredentials = (credentialGetterArgs.credentials ?? []) as {
        id: string;
      }[];
      expect(Array.isArray(allowCredentials)).toBe(true);
      expect(allowCredentials.map((cred) => cred.id)).toEqual([
        "cred-existing",
        "cred-new",
      ]);

      expect(result).toEqual({
        username: "alice",
        credential: parsedAssertion,
        session: "session-token",
        existingDeviceKey: "device-key-123",
      });
    });

    it("derives username from discoverable credential when none provided", async () => {
      const fetchMock = jest.fn().mockResolvedValue({
        ok: true,
        status: 200,
        json: async () => ({
          challenge: "autofill-challenge",
          relyingPartyId: "server-rp",
          timeout: 30000,
          userVerification: "required",
        }),
      });
      baseConfig.fetch = fetchMock;

      const encodedUserHandle = bufferToBase64Url(
        toArrayBuffer(Buffer.from("u|charlie", "utf8"))
      );
      const parsedAssertion = {
        credentialIdB64: "cred-2",
        authenticatorDataB64: "auth-data",
        clientDataJSON_B64: "client-data",
        signatureB64: "signature",
        userHandleB64: encodedUserHandle,
      };
      const credentialGetter = jest.fn().mockResolvedValue(parsedAssertion);

      mockInitiateAuth.mockResolvedValueOnce({
        ChallengeParameters: {
          fido2options: JSON.stringify({
            challenge: "server-challenge",
            relyingPartyId: "server-rp",
          }),
        },
        Session: "session-autofill",
      } as any);

      const result = await prepareFido2SignIn({
        mediation: "conditional",
        credentialGetter,
      });

      expect(fetchMock).toHaveBeenCalledWith(
        "https://example.com/fido2/sign-in-challenge",
        expect.objectContaining({ method: "POST" })
      );
      expect(mockInitiateAuth).toHaveBeenCalledWith(
        expect.objectContaining({
          authflow: "CUSTOM_AUTH",
          authParameters: { USERNAME: "charlie" },
        })
      );
      expect(credentialGetter).toHaveBeenCalledWith(
        expect.objectContaining({
          mediation: "conditional",
          relyingPartyId: TEST_RP.id,
        })
      );
      expect(result).toEqual({
        username: "charlie",
        credential: parsedAssertion,
        session: "session-autofill",
        existingDeviceKey: undefined,
      });
    });

    it("throws when usernameless assertion lacks userHandle", async () => {
      const fetchMock = jest.fn().mockResolvedValue({
        ok: true,
        status: 200,
        json: async () => ({
          challenge: "missing-user-handle",
        }),
      });
      baseConfig.fetch = fetchMock;

      const credentialGetter = jest.fn().mockResolvedValue({
        credentialIdB64: "cred-3",
        authenticatorDataB64: "auth",
        clientDataJSON_B64: "client",
        signatureB64: "sig",
        userHandleB64: null,
      });

      await expect(prepareFido2SignIn({ credentialGetter })).rejects.toThrow(
        "No discoverable credentials available"
      );
    });

    it("throws when discoverable credential maps to sub identifier", async () => {
      const fetchMock = jest.fn().mockResolvedValue({
        ok: true,
        status: 200,
        json: async () => ({
          challenge: "sub-prefix",
        }),
      });
      baseConfig.fetch = fetchMock;

      const encodedUserHandle = bufferToBase64Url(
        toArrayBuffer(Buffer.from("s|123456", "utf8"))
      );
      const credentialGetter = jest.fn().mockResolvedValue({
        credentialIdB64: "cred-4",
        authenticatorDataB64: "auth",
        clientDataJSON_B64: "client",
        signatureB64: "sig",
        userHandleB64: encodedUserHandle,
      });

      await expect(prepareFido2SignIn({ credentialGetter })).rejects.toThrow(
        "Username is required for initiating sign-in"
      );
    });

    describe("conditional mediation session renewal", () => {
      const parsedAssertion = {
        credentialIdB64: "cred-renewal",
        authenticatorDataB64: "auth-data",
        clientDataJSON_B64: "client-data",
        signatureB64: "signature",
        userHandleB64: null,
      };

      const challengeResponse = (n: number) =>
        ({
          ChallengeParameters: {
            fido2options: JSON.stringify({
              challenge: `server-challenge-${n}`,
              relyingPartyId: "server-rp",
            }),
          },
          Session: `session-${n}`,
        }) as any;

      // A conditional credentials.get() that stays pending until aborted,
      // mimicking the browser's autofill behavior
      const pendingUntilAborted = ({ signal }: { signal?: AbortSignal }) =>
        new Promise<never>((_, reject) => {
          signal?.addEventListener("abort", () =>
            reject(new Fido2AbortError())
          );
        });

      afterEach(() => {
        jest.useRealTimers();
      });

      it("renews the Cognito session with a fresh challenge when the conditional request outlives the renewal interval", async () => {
        jest.useFakeTimers();
        mockInitiateAuth
          .mockResolvedValueOnce(challengeResponse(1))
          .mockResolvedValueOnce(challengeResponse(2));

        const credentialGetter = jest
          .fn()
          .mockImplementationOnce(pendingUntilAborted)
          .mockResolvedValueOnce(parsedAssertion);

        const prepared = prepareFido2SignIn({
          username: "alice",
          mediation: "conditional",
          credentialGetter,
        });

        await jest.advanceTimersByTimeAsync(
          COGNITO_AUTH_SESSION_RENEWAL_INTERVAL_MS
        );

        await expect(prepared).resolves.toEqual({
          username: "alice",
          credential: parsedAssertion,
          session: "session-2",
          existingDeviceKey: undefined,
        });

        // The whole CUSTOM_AUTH flow restarted: new session, new challenge
        expect(mockInitiateAuth).toHaveBeenCalledTimes(2);
        expect(credentialGetter).toHaveBeenCalledTimes(2);
        expect(credentialGetter.mock.calls[0][0].challenge).toBe(
          "server-challenge-1"
        );
        expect(credentialGetter.mock.calls[1][0].challenge).toBe(
          "server-challenge-2"
        );
      });

      it("renews repeatedly while the conditional request stays pending", async () => {
        jest.useFakeTimers();
        mockInitiateAuth
          .mockResolvedValueOnce(challengeResponse(1))
          .mockResolvedValueOnce(challengeResponse(2))
          .mockResolvedValueOnce(challengeResponse(3));

        const credentialGetter = jest
          .fn()
          .mockImplementationOnce(pendingUntilAborted)
          .mockImplementationOnce(pendingUntilAborted)
          .mockResolvedValueOnce(parsedAssertion);

        const prepared = prepareFido2SignIn({
          username: "alice",
          mediation: "conditional",
          credentialGetter,
        });

        await jest.advanceTimersByTimeAsync(
          COGNITO_AUTH_SESSION_RENEWAL_INTERVAL_MS
        );
        await jest.advanceTimersByTimeAsync(
          COGNITO_AUTH_SESSION_RENEWAL_INTERVAL_MS
        );

        await expect(prepared).resolves.toEqual(
          expect.objectContaining({ session: "session-3" })
        );
        expect(mockInitiateAuth).toHaveBeenCalledTimes(3);
        expect(credentialGetter).toHaveBeenCalledTimes(3);
      });

      it("does not renew when the credential resolves before the renewal interval", async () => {
        mockInitiateAuth.mockResolvedValueOnce(challengeResponse(1));
        const credentialGetter = jest.fn().mockResolvedValue(parsedAssertion);

        const result = await prepareFido2SignIn({
          username: "alice",
          mediation: "conditional",
          credentialGetter,
        });

        expect(result.session).toBe("session-1");
        expect(mockInitiateAuth).toHaveBeenCalledTimes(1);
        expect(credentialGetter).toHaveBeenCalledTimes(1);
      });

      it("ends the flow instead of renewing when the conditional request was superseded by a newer request", async () => {
        // Regression: a modal passkey sign-in taking over the pending
        // conditional request rejects it with a superseded Fido2AbortError.
        // If that rejection lands at the renewal boundary (after the renewal
        // timer aborts the pending get()), the renewal loop must NOT treat it
        // as its own renewal abort and restart the autofill flow behind the
        // modal request's back.
        jest.useFakeTimers();
        mockInitiateAuth.mockResolvedValueOnce(challengeResponse(1));
        const supersededWhenAborted = ({
          signal,
        }: {
          signal?: AbortSignal;
        }) =>
          new Promise<never>((_, reject) =>
            signal?.addEventListener("abort", () =>
              reject(
                new Fido2AbortError(
                  "WebAuthn operation was aborted: superseded by a newer credential request",
                  "Passkey verification was cancelled",
                  { superseded: true }
                )
              )
            )
          );
        const credentialGetter = jest
          .fn()
          .mockImplementationOnce(supersededWhenAborted);

        const prepared = prepareFido2SignIn({
          username: "alice",
          mediation: "conditional",
          credentialGetter,
        });
        const outcome = prepared.catch((err: unknown) => err);

        await jest.advanceTimersByTimeAsync(
          COGNITO_AUTH_SESSION_RENEWAL_INTERVAL_MS
        );

        const err = await outcome;
        expect(err).toBeInstanceOf(Fido2AbortError);
        expect((err as Fido2AbortError).superseded).toBe(true);
        // No restart: one challenge, one credentials.get()
        expect(mockInitiateAuth).toHaveBeenCalledTimes(1);
        expect(credentialGetter).toHaveBeenCalledTimes(1);
      });

      it("propagates caller aborts instead of renewing", async () => {
        mockInitiateAuth.mockResolvedValueOnce(challengeResponse(1));
        const credentialGetter = jest
          .fn()
          .mockImplementationOnce(pendingUntilAborted);
        const abortController = new AbortController();

        const prepared = prepareFido2SignIn({
          username: "alice",
          mediation: "conditional",
          credentialGetter,
          signal: abortController.signal,
        });

        // Let the flow reach the pending credential request, then abort
        await new Promise((resolve) => setTimeout(resolve, 0));
        abortController.abort();

        await expect(prepared).rejects.toThrow(Fido2AbortError);
        expect(mockInitiateAuth).toHaveBeenCalledTimes(1);
        expect(credentialGetter).toHaveBeenCalledTimes(1);
      });

      it("passes the caller signal straight through for non-conditional mediation", async () => {
        mockInitiateAuth.mockResolvedValueOnce(challengeResponse(1));
        const credentialGetter = jest.fn().mockResolvedValue(parsedAssertion);
        const abortController = new AbortController();

        await prepareFido2SignIn({
          username: "alice",
          mediation: "immediate",
          credentialGetter,
          signal: abortController.signal,
        });

        expect(credentialGetter.mock.calls[0][0].signal).toBe(
          abortController.signal
        );
      });
    });

    it("rejects authenticateWithFido2 when provided username mismatches prepared bundle", async () => {
      const prepared = {
        username: "bundle-user",
        session: "mock-session",
        credential: {
          credentialIdB64: "cred-id",
          authenticatorDataB64: "auth-data",
          clientDataJSON_B64: "client-data",
          signatureB64: "sig",
          userHandleB64: null,
        },
      };

      mockConfigure.mockReturnValue({ ...baseConfig });

      const result = authenticateWithFido2({
        username: "provided-user",
        prepared,
      });

      await expect(result.signedIn).rejects.toThrow(
        /Prepared credentials belong to username/
      );
    });

    it("does not report FIDO2_SIGNIN_FAILED when a conditional sign-in is superseded by a newer request", async () => {
      // A conditional (autofill) request that was aborted because another
      // credential request took over (e.g. a modal sign-in) must stay quiet:
      // it must not clobber the status of the sign-in flow that took over
      const statusCb = jest.fn();
      const credentialGetter = jest
        .fn()
        .mockRejectedValue(
          new Fido2AbortError(
            "WebAuthn operation was aborted: superseded by a newer credential request",
            undefined,
            { superseded: true }
          )
        );

      mockInitiateAuth.mockResolvedValueOnce({
        ChallengeParameters: {
          fido2options: JSON.stringify({
            challenge: "server-challenge",
          }),
        },
        Session: "session-token",
      } as any);

      const { signedIn } = authenticateWithFido2({
        username: "alice",
        mediation: "conditional",
        credentialGetter,
        statusCb,
      });

      await expect(signedIn).rejects.toThrow(Fido2AbortError);
      expect(statusCb).toHaveBeenCalledWith("STARTING_SIGN_IN_WITH_FIDO2");
      expect(statusCb).not.toHaveBeenCalledWith("FIDO2_SIGNIN_FAILED");
    });

    it("reports SIGNED_OUT when a conditional sign-in is aborted by the caller", async () => {
      // A caller-initiated abort is a real cancellation (no other flow is
      // taking over). Unlike a superseded conditional request - which leaves
      // status untouched so the taking-over flow's status survives - this must
      // transition the UI out of its busy state. A deliberate abort is not a
      // failure, so it reports SIGNED_OUT rather than FIDO2_SIGNIN_FAILED
      const statusCb = jest.fn();
      const credentialGetter = jest
        .fn()
        .mockRejectedValue(new Fido2AbortError());

      mockInitiateAuth.mockResolvedValueOnce({
        ChallengeParameters: {
          fido2options: JSON.stringify({
            challenge: "server-challenge",
          }),
        },
        Session: "session-token",
      } as any);

      const { signedIn } = authenticateWithFido2({
        username: "alice",
        mediation: "conditional",
        credentialGetter,
        statusCb,
      });

      await expect(signedIn).rejects.toThrow(Fido2AbortError);
      expect(statusCb).toHaveBeenCalledWith("SIGNED_OUT");
      expect(statusCb).not.toHaveBeenCalledWith("FIDO2_SIGNIN_FAILED");
    });

    it("reports SIGNED_OUT when a modal sign-in is aborted", async () => {
      const statusCb = jest.fn();
      const credentialGetter = jest
        .fn()
        .mockRejectedValue(new Fido2AbortError());

      mockInitiateAuth.mockResolvedValueOnce({
        ChallengeParameters: {
          fido2options: JSON.stringify({
            challenge: "server-challenge",
          }),
        },
        Session: "session-token",
      } as any);

      const { signedIn } = authenticateWithFido2({
        username: "alice",
        credentialGetter,
        statusCb,
      });

      await expect(signedIn).rejects.toThrow(Fido2AbortError);
      expect(statusCb).toHaveBeenCalledWith("SIGNED_OUT");
      expect(statusCb).not.toHaveBeenCalledWith("FIDO2_SIGNIN_FAILED");
    });
  });

  describe("authenticateWithFido2 status on cancellation", () => {
    const prepared = {
      username: "bundle-user",
      session: "mock-session",
      credential: {
        credentialIdB64: "cred-id",
        authenticatorDataB64: "auth-data",
        clientDataJSON_B64: "client-data",
        signatureB64: "sig",
        userHandleB64: null,
      },
    };

    it("does not report FIDO2_SIGNIN_FAILED when the caller aborts a pending sign-in", async () => {
      mockRespondToAuthChallenge.mockImplementationOnce(
        ({ abort: signal }) =>
          new Promise((_resolve, reject) => {
            signal?.addEventListener("abort", () =>
              reject(
                new DOMException("The operation was aborted.", "AbortError")
              )
            );
          })
      );

      const statusCb = jest.fn();
      const { signedIn, abort } = authenticateWithFido2({
        prepared,
        statusCb,
      });
      // Let the flow reach respondToAuthChallenge before cancelling
      await new Promise((resolve) => setTimeout(resolve, 0));
      abort();

      await expect(signedIn).rejects.toThrow("aborted");
      const statuses = statusCb.mock.calls.map(([status]) => status);
      expect(statuses).not.toContain("FIDO2_SIGNIN_FAILED");
      expect(statuses[statuses.length - 1]).toBe("SIGNED_OUT");
    });

    it("does not report FIDO2_SIGNIN_FAILED when WebAuthn is cancelled (Fido2AbortError)", async () => {
      mockRespondToAuthChallenge.mockRejectedValueOnce(new Fido2AbortError());

      const statusCb = jest.fn();
      const { signedIn } = authenticateWithFido2({ prepared, statusCb });

      await expect(signedIn).rejects.toThrow(Fido2AbortError);
      const statuses = statusCb.mock.calls.map(([status]) => status);
      expect(statuses).not.toContain("FIDO2_SIGNIN_FAILED");
      expect(statuses[statuses.length - 1]).toBe("SIGNED_OUT");
    });

    it("still reports FIDO2_SIGNIN_FAILED for genuine failures", async () => {
      mockRespondToAuthChallenge.mockRejectedValueOnce(
        new Error("Incorrect username or password.")
      );

      const statusCb = jest.fn();
      const { signedIn } = authenticateWithFido2({ prepared, statusCb });

      await expect(signedIn).rejects.toThrow("Incorrect username or password.");
      const statuses = statusCb.mock.calls.map(([status]) => status);
      expect(statuses[statuses.length - 1]).toBe("FIDO2_SIGNIN_FAILED");
    });
  });
});
