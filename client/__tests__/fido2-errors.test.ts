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
  fido2CreateCredential,
  fido2getCredential,
  fido2StartCreateCredential,
  fido2ListCredentials,
  fido2DeleteCredential,
  fido2UpdateCredential,
} from "../fido2.js";
import {
  Fido2AbortError,
  Fido2CredentialError,
  Fido2ConfigError,
  Fido2AuthError,
} from "../errors.js";
import type { ConfigWithDefaults } from "../config.js";
import { configure } from "../config.js";
import type { TokensFromStorage } from "../storage.js";
import { retrieveTokens } from "../storage.js";

// Mock dependencies
jest.mock("../config");
jest.mock("../storage");

const mockConfigure = configure as jest.MockedFunction<typeof configure>;
const mockRetrieveTokens = retrieveTokens as jest.MockedFunction<
  typeof retrieveTokens
>;

// Helper to create a mock config
const createMockConfig = (
  overrides: Partial<ConfigWithDefaults> = {}
): ConfigWithDefaults => ({
  cognitoIdpEndpoint: "https://cognito-idp.us-east-1.amazonaws.com",
  clientId: "test-client-id",
  storage: {
    getItem: jest.fn(),
    setItem: jest.fn(),
    removeItem: jest.fn(),
  },
  crypto: {
    getRandomValues: jest.fn() as unknown as Crypto["getRandomValues"],
    subtle: {
      digest: jest.fn(),
      importKey: jest.fn(),
      sign: jest.fn(),
    } as unknown as SubtleCrypto,
  },
  fetch: jest.fn(),
  location: { hostname: "localhost", href: "http://localhost" },
  history: { pushState: jest.fn() },
  ...overrides,
});

describe("fido2.ts error handling", () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe("Configuration errors", () => {
    it("should throw Fido2ConfigError when fido2 config is missing", async () => {
      mockConfigure.mockReturnValue(
        createMockConfig({
          fido2: undefined,
        })
      );

      await expect(fido2StartCreateCredential()).rejects.toThrow(
        Fido2ConfigError
      );
      await expect(fido2StartCreateCredential()).rejects.toThrow(
        "Fido2 configuration not initialized"
      );
    });

    it("should throw Fido2ConfigError for list credentials without config", async () => {
      mockConfigure.mockReturnValue(
        createMockConfig({
          fido2: undefined,
        })
      );

      await expect(fido2ListCredentials()).rejects.toThrow(Fido2ConfigError);
    });

    it("should throw Fido2ConfigError for delete credential without config", async () => {
      mockConfigure.mockReturnValue(
        createMockConfig({
          fido2: undefined,
        })
      );

      await expect(
        fido2DeleteCredential({ credentialId: "test" })
      ).rejects.toThrow(Fido2ConfigError);
    });

    it("should throw Fido2ConfigError for update credential without config", async () => {
      mockConfigure.mockReturnValue(
        createMockConfig({
          fido2: undefined,
        })
      );

      await expect(
        fido2UpdateCredential({ credentialId: "test", friendlyName: "Test" })
      ).rejects.toThrow(Fido2ConfigError);
    });
  });

  describe("Authentication errors", () => {
    beforeEach(() => {
      mockConfigure.mockReturnValue(
        createMockConfig({
          fido2: { baseUrl: "https://example.com" },
        })
      );
    });

    it("should throw Fido2AuthError when no token available for start create", async () => {
      mockRetrieveTokens.mockResolvedValue(undefined);

      await expect(fido2StartCreateCredential()).rejects.toThrow(
        Fido2AuthError
      );
      await expect(fido2StartCreateCredential()).rejects.toThrow(
        "No authentication token available"
      );
    });

    it("should throw Fido2AuthError when no token available for list", async () => {
      mockRetrieveTokens.mockResolvedValue(undefined);

      await expect(fido2ListCredentials()).rejects.toThrow(Fido2AuthError);
    });

    it("should throw Fido2AuthError when no token available for delete", async () => {
      mockRetrieveTokens.mockResolvedValue(undefined);

      await expect(
        fido2DeleteCredential({ credentialId: "test" })
      ).rejects.toThrow(Fido2AuthError);
    });

    it("should throw Fido2AuthError when no token available for update", async () => {
      mockRetrieveTokens.mockResolvedValue(undefined);

      await expect(
        fido2UpdateCredential({ credentialId: "test", friendlyName: "Test" })
      ).rejects.toThrow(Fido2AuthError);
    });

    it("should throw Fido2AuthError when tokens object exists but idToken is missing", async () => {
      mockRetrieveTokens.mockResolvedValue({
        username: "testuser",
        accessToken: "token",
      } as Partial<TokensFromStorage> as TokensFromStorage);

      await expect(fido2ListCredentials()).rejects.toThrow(Fido2AuthError);
    });
  });

  describe("WebAuthn API error conversion", () => {
    beforeEach(() => {
      mockConfigure.mockReturnValue(
        createMockConfig({
          fido2: { baseUrl: "https://example.com" },
          debug: jest.fn(),
        })
      );
    });

    describe("fido2CreateCredential", () => {
      it("should convert DOMException AbortError to Fido2AbortError", async () => {
        mockRetrieveTokens.mockResolvedValue({
          username: "testuser",
          idToken: "test-token",
        } as Partial<TokensFromStorage> as TokensFromStorage);

        const mockFetch = jest.fn().mockResolvedValue({
          ok: true,
          json: async () => ({
            challenge: "test-challenge",
            rp: { name: "Test RP" },
            user: { id: "user-123", name: "test", displayName: "Test User" },
            pubKeyCredParams: [{ type: "public-key", alg: -7 }],
            timeout: 60000,
            excludeCredentials: [],
            authenticatorSelection: { userVerification: "preferred" },
          }),
        });

        mockConfigure.mockReturnValue(
          createMockConfig({
            fido2: { baseUrl: "https://example.com" },
            fetch: mockFetch,
            debug: jest.fn(),
          })
        );

        // Mock navigator.credentials.create to throw AbortError
        const mockCreate = jest
          .fn()
          .mockRejectedValue(new DOMException("Aborted", "AbortError"));
        Object.defineProperty(global.navigator, "credentials", {
          value: { create: mockCreate },
          configurable: true,
        });

        await expect(
          fido2CreateCredential({ friendlyName: "Test" })
        ).rejects.toThrow(Fido2AbortError);
      });

      it("should convert DOMException NotAllowedError to Fido2CredentialError", async () => {
        mockRetrieveTokens.mockResolvedValue({
          username: "testuser",
          idToken: "test-token",
        } as Partial<TokensFromStorage> as TokensFromStorage);

        const mockFetch = jest.fn().mockResolvedValue({
          ok: true,
          json: async () => ({
            challenge: "test-challenge",
            rp: { name: "Test RP" },
            user: { id: "user-123", name: "test", displayName: "Test User" },
            pubKeyCredParams: [{ type: "public-key", alg: -7 }],
            timeout: 60000,
            excludeCredentials: [],
            authenticatorSelection: { userVerification: "preferred" },
          }),
        });

        mockConfigure.mockReturnValue(
          createMockConfig({
            fido2: { baseUrl: "https://example.com" },
            fetch: mockFetch,
            debug: jest.fn(),
          })
        );

        const mockCreate = jest
          .fn()
          .mockRejectedValue(
            new DOMException("User denied", "NotAllowedError")
          );
        Object.defineProperty(global.navigator, "credentials", {
          value: { create: mockCreate },
          configurable: true,
        });

        await expect(
          fido2CreateCredential({ friendlyName: "Test" })
        ).rejects.toThrow(Fido2CredentialError);
      });

      it("should throw Fido2CredentialError when no credential returned", async () => {
        mockRetrieveTokens.mockResolvedValue({
          username: "testuser",
          idToken: "test-token",
        } as Partial<TokensFromStorage> as TokensFromStorage);

        const mockFetch = jest.fn().mockResolvedValue({
          ok: true,
          json: async () => ({
            challenge: "test-challenge",
            rp: { name: "Test RP" },
            user: { id: "user-123", name: "test", displayName: "Test User" },
            pubKeyCredParams: [{ type: "public-key", alg: -7 }],
            timeout: 60000,
            excludeCredentials: [],
            authenticatorSelection: { userVerification: "preferred" },
          }),
        });

        mockConfigure.mockReturnValue(
          createMockConfig({
            fido2: { baseUrl: "https://example.com" },
            fetch: mockFetch,
            debug: jest.fn(),
          })
        );

        const mockCreate = jest.fn().mockResolvedValue(null);
        Object.defineProperty(global.navigator, "credentials", {
          value: { create: mockCreate },
          configurable: true,
        });

        await expect(
          fido2CreateCredential({ friendlyName: "Test" })
        ).rejects.toThrow(Fido2CredentialError);
        await expect(
          fido2CreateCredential({ friendlyName: "Test" })
        ).rejects.toThrow("No credential returned from browser");
      });
    });

    describe("fido2getCredential", () => {
      it("should convert DOMException AbortError to Fido2AbortError", async () => {
        const mockGet = jest
          .fn()
          .mockRejectedValue(new DOMException("Aborted", "AbortError"));
        Object.defineProperty(global.navigator, "credentials", {
          value: { get: mockGet },
          configurable: true,
        });

        await expect(
          fido2getCredential({
            challenge: "test-challenge",
            relyingPartyId: "example.com",
          })
        ).rejects.toThrow(Fido2AbortError);
      });

      it("should convert DOMException SecurityError to Fido2ConfigError", async () => {
        const mockGet = jest
          .fn()
          .mockRejectedValue(
            new DOMException("Invalid domain", "SecurityError")
          );
        Object.defineProperty(global.navigator, "credentials", {
          value: { get: mockGet },
          configurable: true,
        });

        await expect(
          fido2getCredential({
            challenge: "test-challenge",
            relyingPartyId: "example.com",
          })
        ).rejects.toThrow(Fido2ConfigError);
      });

      it("should throw Fido2CredentialError when no credential returned", async () => {
        const mockGet = jest.fn().mockResolvedValue(null);
        Object.defineProperty(global.navigator, "credentials", {
          value: { get: mockGet },
          configurable: true,
        });

        await expect(
          fido2getCredential({
            challenge: "test-challenge",
            relyingPartyId: "example.com",
          })
        ).rejects.toThrow(Fido2CredentialError);
      });

      it("should pass AbortSignal to navigator.credentials.get", async () => {
        const abortController = new AbortController();
        const mockGet = jest
          .fn()
          .mockRejectedValue(new DOMException("Aborted", "AbortError"));
        Object.defineProperty(global.navigator, "credentials", {
          value: { get: mockGet },
          configurable: true,
        });

        await expect(
          fido2getCredential({
            challenge: "test-challenge",
            relyingPartyId: "example.com",
            signal: abortController.signal,
          })
        ).rejects.toThrow(Fido2AbortError);

        expect(mockGet).toHaveBeenCalledWith(
          expect.objectContaining({
            signal: abortController.signal,
          })
        );
      });
    });
  });

  describe("Error code verification", () => {
    it("should use correct error codes", async () => {
      mockConfigure.mockReturnValue(
        createMockConfig({
          fido2: undefined,
        })
      );

      try {
        await fido2StartCreateCredential();
        fail("Should have thrown");
      } catch (error) {
        expect(error).toBeInstanceOf(Fido2ConfigError);
        expect((error as Fido2ConfigError).code).toBe("CONFIG_ERROR");
      }

      mockConfigure.mockReturnValue(
        createMockConfig({
          fido2: { baseUrl: "https://example.com" },
        })
      );
      mockRetrieveTokens.mockResolvedValue(undefined);

      try {
        await fido2StartCreateCredential();
        fail("Should have thrown");
      } catch (error) {
        expect(error).toBeInstanceOf(Fido2AuthError);
        expect((error as Fido2AuthError).code).toBe("AUTH_ERROR");
      }
    });
  });
});
