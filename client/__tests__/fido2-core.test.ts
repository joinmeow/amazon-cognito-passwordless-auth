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
  fido2CreateCredential,
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
import { retrieveDeviceKey, retrieveTokens } from "../storage.js";
import { bufferToBase64Url } from "../util.js";
import {
  TextDecoder as NodeTextDecoder,
  TextEncoder as NodeTextEncoder,
} from "util";

if (typeof globalThis.TextDecoder === "undefined") {
  (
    globalThis as unknown as { TextDecoder: typeof NodeTextDecoder }
  ).TextDecoder = NodeTextDecoder;
}

if (typeof globalThis.TextEncoder === "undefined") {
  (
    globalThis as unknown as { TextEncoder: typeof NodeTextEncoder }
  ).TextEncoder = NodeTextEncoder;
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
const mockRetrieveTokens = retrieveTokens as jest.MockedFunction<
  typeof retrieveTokens
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

    describe("user handle (user.id) encoding", () => {
      const startCreateResponse = (userId: string) => ({
        ok: true,
        json: async () => ({
          challenge: "test-challenge",
          rp: { name: TEST_RP.name, id: TEST_RP.id },
          user: { id: userId, name: "test", displayName: "Test User" },
          pubKeyCredParams: [{ type: "public-key", alg: -7 }],
          timeout: 60000,
          excludeCredentials: [],
          authenticatorSelection: { userVerification: "preferred" },
        }),
      });

      const captureUserHandle = async (userId: string) => {
        mockRetrieveTokens.mockResolvedValue({
          username: "testuser",
          idToken: "test-token",
        } as Awaited<ReturnType<typeof retrieveTokens>>);
        (baseConfig.fetch as jest.Mock).mockResolvedValue(
          startCreateResponse(userId)
        );
        // Return null from create() so fido2CreateCredential throws after
        // we have captured the assembled publicKey options
        const mockCreate = jest.fn().mockResolvedValue(null);
        Object.defineProperty(global.navigator, "credentials", {
          value: { create: mockCreate },
          configurable: true,
        });
        await expect(
          fido2CreateCredential({ friendlyName: "Test" })
        ).rejects.toThrow(Fido2CredentialError);
        const { publicKey } = mockCreate.mock.calls[0][0] as {
          publicKey: { user: { id: Uint8Array } };
        };
        return publicKey.user.id;
      };

      it("round-trips non-ASCII user handles through the sign-in decoder", async () => {
        const userId = "u|Ünïcødé用户";
        const userHandle = await captureUserHandle(userId);
        // Sign-in decodes the userHandle with TextDecoder (UTF-8), so the
        // registered bytes must decode back to the exact same string
        expect(new TextDecoder().decode(userHandle)).toBe(userId);
        // The old Latin-1 byte-stuffing encoding corrupted these bytes
        expect(Array.from(userHandle)).not.toEqual(
          Array.from(userId, (c) => c.charCodeAt(0))
        );
      });

      it("encodes ASCII user handles identically to the previous encoding", async () => {
        const userId = "u|user-123";
        const userHandle = await captureUserHandle(userId);
        expect(Array.from(userHandle)).toEqual(
          Array.from(userId, (c) => c.charCodeAt(0))
        );
        expect(new TextDecoder().decode(userHandle)).toBe(userId);
      });

      it("throws a clear error when the user handle exceeds 64 bytes", async () => {
        const userId = `u|${"用".repeat(22)}`; // 2 + 22 * 3 = 68 bytes UTF-8
        mockRetrieveTokens.mockResolvedValue({
          username: "testuser",
          idToken: "test-token",
        } as Awaited<ReturnType<typeof retrieveTokens>>);
        (baseConfig.fetch as jest.Mock).mockResolvedValue(
          startCreateResponse(userId)
        );
        const mockCreate = jest.fn();
        Object.defineProperty(global.navigator, "credentials", {
          value: { create: mockCreate },
          configurable: true,
        });
        await expect(
          fido2CreateCredential({ friendlyName: "Test" })
        ).rejects.toThrow(Fido2ValidationError);
        await expect(
          fido2CreateCredential({ friendlyName: "Test" })
        ).rejects.toThrow("User handle must not exceed 64 bytes");
        expect(mockCreate).not.toHaveBeenCalled();
      });
    });
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

      it("rides out a transient renewal-initiate failure (retries then succeeds) without ending the flow", async () => {
        // A network blip on the per-renewal initiateFido2Challenge() must not
        // kill the still-pending autofill request: the renewal retries with
        // backoff and the flow ultimately resolves with the assertion.
        jest.useFakeTimers();
        mockInitiateAuth
          .mockResolvedValueOnce(challengeResponse(1)) // first challenge
          .mockRejectedValueOnce(new Error("network blip 1")) // renewal try 1
          .mockRejectedValueOnce(new Error("network blip 2")) // renewal try 2
          .mockResolvedValueOnce(challengeResponse(2)); // renewal try 3 OK

        const credentialGetter = jest
          .fn()
          .mockImplementationOnce(pendingUntilAborted)
          .mockResolvedValueOnce(parsedAssertion);

        const prepared = prepareFido2SignIn({
          username: "alice",
          mediation: "conditional",
          credentialGetter,
        });
        const settled = prepared.then(
          (value) => ({ value }),
          (error: unknown) => ({ error })
        );

        // Reach the renewal boundary: the pending get() is aborted and the
        // renewal initiate begins (and fails transiently).
        await jest.advanceTimersByTimeAsync(
          COGNITO_AUTH_SESSION_RENEWAL_INTERVAL_MS
        );
        // Advance through both retry backoffs (1s then 2s).
        await jest.advanceTimersByTimeAsync(1000);
        await jest.advanceTimersByTimeAsync(2000);

        const outcome = await settled;
        expect(outcome).toEqual({
          value: {
            username: "alice",
            credential: parsedAssertion,
            session: "session-2",
            existingDeviceKey: undefined,
          },
        });
        // 4 initiate calls: 1 first challenge + 3 renewal attempts (2 fail, 1 ok)
        expect(mockInitiateAuth).toHaveBeenCalledTimes(4);
        expect(credentialGetter).toHaveBeenCalledTimes(2);
      });

      it("ends the flow when renewal-initiate fails more than the retry budget", async () => {
        // Retries are bounded: once the budget is exhausted the failure
        // propagates and ends the prepared flow (it rejects), rather than
        // retrying forever.
        jest.useFakeTimers();
        mockInitiateAuth
          .mockResolvedValueOnce(challengeResponse(1)) // first challenge
          .mockRejectedValue(new Error("persistent network failure")); // all renewals

        const credentialGetter = jest
          .fn()
          .mockImplementationOnce(pendingUntilAborted)
          .mockResolvedValueOnce(parsedAssertion);

        const prepared = prepareFido2SignIn({
          username: "alice",
          mediation: "conditional",
          credentialGetter,
        });
        const outcome = prepared.catch((err: unknown) => err);

        await jest.advanceTimersByTimeAsync(
          COGNITO_AUTH_SESSION_RENEWAL_INTERVAL_MS
        );
        // Exhaust both backoffs between the 3 attempts.
        await jest.advanceTimersByTimeAsync(1000);
        await jest.advanceTimersByTimeAsync(2000);

        const err = await outcome;
        expect(err).toBeInstanceOf(Error);
        expect((err as Error).message).toBe("persistent network failure");
        // 1 first challenge + exactly RENEWAL_INITIATE_MAX_ATTEMPTS (3) renewals
        expect(mockInitiateAuth).toHaveBeenCalledTimes(4);
        // The second get() never ran: the flow ended on exhausted retries
        expect(credentialGetter).toHaveBeenCalledTimes(1);
      });

      it("ends the flow promptly on a caller abort during the renewal-initiate backoff", async () => {
        // A supersede/abort during the retry backoff must end the flow
        // immediately, not after the retry budget is exhausted.
        jest.useFakeTimers();
        mockInitiateAuth
          .mockResolvedValueOnce(challengeResponse(1)) // first challenge
          .mockRejectedValue(new Error("network blip")); // renewals keep failing

        const credentialGetter = jest
          .fn()
          .mockImplementationOnce(pendingUntilAborted)
          .mockResolvedValueOnce(parsedAssertion);
        const abortController = new AbortController();

        const prepared = prepareFido2SignIn({
          username: "alice",
          mediation: "conditional",
          credentialGetter,
          signal: abortController.signal,
        });
        const outcome = prepared.catch((err: unknown) => err);

        // Reach the renewal boundary; the first renewal attempt fails and we
        // enter the (1s) backoff.
        await jest.advanceTimersByTimeAsync(
          COGNITO_AUTH_SESSION_RENEWAL_INTERVAL_MS
        );
        // Abort mid-backoff (before the 1s elapses): the flow must end now,
        // without consuming the remaining retry attempts.
        abortController.abort();
        await jest.advanceTimersByTimeAsync(0);

        const err = await outcome;
        expect(err).toBeInstanceOf(Fido2AbortError);
        // 1 first challenge + only 1 renewal attempt before the abort ended it
        expect(mockInitiateAuth).toHaveBeenCalledTimes(2);
        expect(credentialGetter).toHaveBeenCalledTimes(1);
      });

      it("ends the flow promptly when a modal takeover supersedes it during the renewal-initiate backoff", async () => {
        // The harder supersede case: a modal "sign in with passkey" takeover
        // marks the conditional flow superseded but does NOT abort the
        // conditional caller's own signal (only a non-conditional request taking
        // the credentials.get() lock sets activeConditionalFlow.superseded). The
        // initiate-retry backoff therefore cannot rely on the caller signal — it
        // must wake on the supersede itself and end the flow at once, instead of
        // sleeping out the full backoff behind the now-foreground modal sign-in.
        jest.useFakeTimers();
        mockInitiateAuth
          .mockResolvedValueOnce(challengeResponse(1)) // conditional first challenge
          .mockRejectedValue(new Error("network blip")); // renewals keep failing

        const credentialGetter = jest
          .fn()
          .mockImplementationOnce(pendingUntilAborted)
          .mockResolvedValueOnce(parsedAssertion);

        // The modal takeover goes through the REAL fido2getCredential, which
        // takes the lock and marks the active conditional flow superseded. A
        // direct challenge is supplied, so it issues navigator.credentials.get
        // without an initiateAuth round-trip of its own.
        const modalGet = jest.fn().mockResolvedValue(MOCK_ASSERTION_CREDENTIAL);
        cleanup = setupWebAuthnMock({
          customCredentials: { get: modalGet, create: jest.fn() } as never,
        });

        const prepared = prepareFido2SignIn({
          username: "alice",
          mediation: "conditional",
          credentialGetter,
        });
        let settled: { value: unknown } | { error: unknown } | undefined;
        void prepared.then(
          (value) => (settled = { value }),
          (error: unknown) => (settled = { error })
        );

        // Reach the renewal boundary: the first renewal initiate fails and the
        // flow enters its (1s) backoff. It must NOT have ended yet.
        await jest.advanceTimersByTimeAsync(
          COGNITO_AUTH_SESSION_RENEWAL_INTERVAL_MS
        );
        expect(settled).toBeUndefined();

        // Modal takeover mid-backoff: marks the conditional flow superseded.
        const modal = fido2getCredential({
          challenge: TEST_CHALLENGES.basic,
        }).catch((err: unknown) => err);

        // Flush microtasks ONLY — do NOT advance the 1s backoff. With the
        // supersede-driven wake the flow has already ended; without it (the bug)
        // it would still be sleeping and `settled` would remain undefined.
        await jest.advanceTimersByTimeAsync(0);
        await jest.advanceTimersByTimeAsync(0);

        expect(settled).toBeDefined();
        const { error } = settled as { error: unknown };
        expect(error).toBeInstanceOf(Fido2AbortError);
        expect((error as Fido2AbortError).superseded).toBe(true);

        // The takeover itself proceeded, and the backoff was cut short: only the
        // first challenge + the single failed renewal initiate ran (no further
        // renewal attempts were consumed waiting out the backoff).
        await modal;
        expect(modalGet).toHaveBeenCalledTimes(1);
        expect(mockInitiateAuth).toHaveBeenCalledTimes(2);
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

      it("ends the flow when a modal takeover lands during the renewal initiate-challenge window (no get pending)", async () => {
        // Gap the per-get supersede tracker misses: between renewal
        // iterations, the previous get() has been aborted and the next has
        // not been issued (e.g. while initiating a fresh challenge), so
        // pendingConditionalGet is momentarily undefined. A modal takeover in
        // that window must still end the conditional flow via the
        // flow-lifetime marker, instead of the autofill re-arming forever
        // behind the modal sign-in.
        jest.useFakeTimers();
        // Real navigator mock so the modal fido2getCredential can succeed
        cleanup = setupWebAuthnMock({ credential: MOCK_ASSERTION_CREDENTIAL });

        let modalCompleted = false;
        mockInitiateAuth
          .mockResolvedValueOnce(challengeResponse(1))
          .mockImplementationOnce(async () => {
            // A modal passkey sign-in completes WHILE we are initiating the
            // renewal challenge — exactly the no-get-pending window. It must
            // supersede the active conditional flow.
            await fido2getCredential({ challenge: TEST_CHALLENGES.basic });
            modalCompleted = true;
            return challengeResponse(2);
          });

        const credentialGetter = jest
          .fn()
          .mockImplementationOnce(pendingUntilAborted);

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
        expect(modalCompleted).toBe(true);
        // The autofill flow did NOT re-arm behind the modal: its credential
        // getter ran exactly once (the first, aborted iteration).
        expect(credentialGetter).toHaveBeenCalledTimes(1);
      });

      it("does not complete a superseded flow when the conditional credential resolves in the same tick as a takeover", async () => {
        // Race: a modal takeover marks the flow superseded (via the lock) at
        // the same time the conditional getter resolves with a valid
        // credential — e.g. an injected getter the takeover's abort never
        // reaches. The success branch must honour the superseded marker and
        // end the flow, not complete the (superseded) conditional sign-in.
        jest.useFakeTimers();
        cleanup = setupWebAuthnMock({ credential: MOCK_ASSERTION_CREDENTIAL });

        mockInitiateAuth.mockResolvedValueOnce(challengeResponse(1));

        // The conditional getter performs a modal takeover and THEN resolves
        // with a credential, in that order, without ever observing its abort
        // signal — exactly the same-tick success-vs-supersede race.
        const credentialGetter = jest.fn().mockImplementationOnce(async () => {
          await fido2getCredential({ challenge: TEST_CHALLENGES.basic });
          return parsedAssertion;
        });

        const prepared = prepareFido2SignIn({
          username: "alice",
          mediation: "conditional",
          credentialGetter,
        });
        const outcome = prepared.catch((err: unknown) => err);
        await jest.advanceTimersByTimeAsync(0);

        const err = await outcome;
        expect(err).toBeInstanceOf(Fido2AbortError);
        expect((err as Fido2AbortError).superseded).toBe(true);
      });

      it("ends the flow instead of renewing when the conditional request was superseded by a newer request", async () => {
        // Belt-and-suspenders: even relying only on the per-get error's
        // superseded flag (the flow-lifetime marker aside), a superseded
        // abort landing at the renewal boundary must end the flow, not
        // restart it.
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
