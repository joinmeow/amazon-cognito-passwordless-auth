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

import { TextEncoder, TextDecoder } from "util";

// jsdom doesn't provide TextEncoder/TextDecoder
Object.assign(globalThis, { TextEncoder, TextDecoder });

import {
  handleCognitoOAuthCallback,
  signInWithRedirect,
} from "../hosted-oauth.js";
import { webcrypto } from "crypto";
import { configure, getAuthorizeEndpoint } from "../config.js";
import { processTokens } from "../common.js";
import { withStorageLock, LockTimeoutError } from "../lock.js";
import type { ConfigWithDefaults } from "../config.js";

// Mock dependencies
jest.mock("../config");
jest.mock("../common");
jest.mock("../lock");
jest.mock("../storage");

const mockConfigure = configure as jest.MockedFunction<typeof configure>;
const mockGetAuthorizeEndpoint = getAuthorizeEndpoint as jest.MockedFunction<
  typeof getAuthorizeEndpoint
>;
const mockProcessTokens = processTokens as jest.MockedFunction<
  typeof processTokens
>;
const mockWithStorageLock = withStorageLock as jest.MockedFunction<
  typeof withStorageLock
>;

interface MockLocation {
  href: string;
  origin: string;
  pathname: string;
  search: string;
  hash: string;
  hostname: string;
}

interface MockStorage {
  getItem: jest.Mock;
  setItem: jest.Mock;
  removeItem: jest.Mock;
}

describe("OAuth Integration with processTokens", () => {
  let mockConfig: Partial<ConfigWithDefaults> & {
    storage: MockStorage;
    location: MockLocation;
    history: { pushState: jest.Mock; replaceState: jest.Mock };
  };
  let mockLocation: MockLocation;
  let mockHistory: { pushState: jest.Mock; replaceState: jest.Mock };
  let mockStorage: MockStorage;
  let mockFetch: jest.Mock;

  beforeEach(() => {
    jest.clearAllMocks();

    mockLocation = {
      href: "https://app.example.com/signin-redirect?code=test-code&state=test-state",
      origin: "https://app.example.com",
      pathname: "/signin-redirect",
      search: "?code=test-code&state=test-state",
      hash: "",
      hostname: "app.example.com",
    };

    mockHistory = {
      pushState: jest.fn(),
      replaceState: jest.fn(),
    };

    mockStorage = {
      getItem: jest.fn(),
      setItem: jest.fn(),
      removeItem: jest.fn(),
    } as MockStorage;

    mockFetch = jest.fn();

    mockConfig = {
      clientId: "test-client-id",
      hostedUi: {
        redirectSignIn: "https://app.example.com/signin-redirect",
        responseType: "code",
      },
      location: mockLocation,
      history: mockHistory,
      storage: mockStorage,
      fetch: mockFetch,
      debug: jest.fn(),
    };

    mockConfigure.mockReturnValue(mockConfig as ConfigWithDefaults);
    mockWithStorageLock.mockImplementation(async (_, fn) => fn());
  });

  describe("handleCognitoOAuthCallback", () => {
    it("should handle OAuth code flow and use processTokens", async () => {
      // Setup OAuth state
      mockStorage.getItem.mockImplementation((key: string) => {
        if (key === "cognito_oauth_in_progress") return Promise.resolve("true");
        if (key === "cognito_oauth_state") return Promise.resolve("test-state");
        if (key === "cognito_oauth_pkce")
          return Promise.resolve("test-verifier");
        return Promise.resolve(null);
      });

      // Mock token exchange response
      const mockTokenResponse = {
        access_token: "mock-access-token",
        id_token: "mock-id-token",
        refresh_token: "mock-refresh-token",
        expires_in: 3600,
        token_type: "Bearer",
      };

      mockFetch.mockResolvedValue({
        ok: true,
        json: async () => mockTokenResponse,
      });

      // Mock processTokens to return the processed tokens
      const processedTokens = {
        accessToken: "mock-access-token",
        idToken: "mock-id-token",
        refreshToken: "mock-refresh-token",
        expireAt: new Date(Date.now() + 3600000),
        username: "test-user",
        authMethod: "REDIRECT" as const,
      };
      mockProcessTokens.mockResolvedValue(processedTokens);

      // Call handleCognitoOAuthCallback
      const result = await handleCognitoOAuthCallback();

      // Verify processTokens was called with correct parameters
      expect(mockProcessTokens).toHaveBeenCalledWith({
        accessToken: "mock-access-token",
        idToken: "mock-id-token",
        refreshToken: "mock-refresh-token",
        expireAt: expect.any(Date) as Date,
        username: "test-user",
        authMethod: "REDIRECT",
        newDeviceMetadata: undefined,
        userConfirmationNecessary: false,
      });

      // Verify the result
      expect(result).toEqual(processedTokens);

      // Verify cleanup
      expect(mockStorage.removeItem).toHaveBeenCalledWith(
        "cognito_oauth_state"
      );
      expect(mockStorage.removeItem).toHaveBeenCalledWith("cognito_oauth_pkce");
      expect(mockStorage.removeItem).toHaveBeenCalledWith(
        "cognito_oauth_in_progress"
      );
    });

    it("should handle OAuth implicit flow and use processTokens", async () => {
      // Setup for implicit flow
      mockLocation.href =
        "https://app.example.com/signin-redirect#access_token=mock-access-token&id_token=mock-id-token&expires_in=3600&state=test-state";
      mockLocation.hash =
        "#access_token=mock-access-token&id_token=mock-id-token&expires_in=3600&state=test-state";
      mockLocation.search = "";
      mockConfig.hostedUi!.responseType = "token";

      mockStorage.getItem.mockImplementation((key: string) => {
        if (key === "cognito_oauth_in_progress") return Promise.resolve("true");
        if (key === "cognito_oauth_state") return Promise.resolve("test-state");
        return Promise.resolve(null);
      });

      // Mock processTokens
      const processedTokens = {
        accessToken: "mock-access-token",
        idToken: "mock-id-token",
        refreshToken: "",
        expireAt: new Date(Date.now() + 3600000),
        username: "test-user",
        authMethod: "REDIRECT" as const,
      };
      mockProcessTokens.mockResolvedValue(processedTokens);

      // Call handleCognitoOAuthCallback
      const result = await handleCognitoOAuthCallback();

      // Verify processTokens was called
      expect(mockProcessTokens).toHaveBeenCalledWith({
        accessToken: "mock-access-token",
        idToken: "mock-id-token",
        refreshToken: "",
        expireAt: expect.any(Date) as Date,
        username: "test-user",
        authMethod: "REDIRECT",
        newDeviceMetadata: undefined,
        userConfirmationNecessary: false,
      });

      expect(result).toEqual(processedTokens);
    });

    it("should handle missing ID token in OAuth response", async () => {
      mockStorage.getItem.mockImplementation((key: string) => {
        if (key === "cognito_oauth_in_progress") return Promise.resolve("true");
        if (key === "cognito_oauth_state") return Promise.resolve("test-state");
        if (key === "cognito_oauth_pkce")
          return Promise.resolve("test-verifier");
        return Promise.resolve(null);
      });

      // Mock token response without ID token
      const mockTokenResponse = {
        access_token: "mock-access-token",
        refresh_token: "mock-refresh-token",
        expires_in: 3600,
        token_type: "Bearer",
      };

      mockFetch.mockResolvedValue({
        ok: true,
        json: async () => mockTokenResponse,
      });

      const processedTokens = {
        accessToken: "mock-access-token",
        idToken: "",
        refreshToken: "mock-refresh-token",
        expireAt: new Date(Date.now() + 3600000),
        username: "test-user",
        authMethod: "REDIRECT" as const,
      };
      mockProcessTokens.mockResolvedValue(processedTokens);

      const result = await handleCognitoOAuthCallback();

      // Verify processTokens was called with empty idToken
      expect(mockProcessTokens).toHaveBeenCalledWith({
        accessToken: "mock-access-token",
        idToken: "", // Empty string when missing
        refreshToken: "mock-refresh-token",
        expireAt: expect.any(Date) as Date,
        username: "test-user",
        authMethod: "REDIRECT",
        newDeviceMetadata: undefined,
        userConfirmationNecessary: false,
      });

      expect(result).toEqual(processedTokens);
    });

    it("should return null when no OAuth flow is in progress", async () => {
      mockStorage.getItem.mockResolvedValue("false");

      const result = await handleCognitoOAuthCallback();

      expect(result).toBeNull();
      expect(mockProcessTokens).not.toHaveBeenCalled();
    });

    it("should not touch the in-progress flag when invoked on a non-callback URL", async () => {
      // Flow in flight, but current URL is NOT the configured redirect URL
      // (e.g. another tab loads a page with an unrelated ?code=... param)
      mockLocation.href = "https://app.example.com/some-other-page?code=COUPON";
      mockLocation.pathname = "/some-other-page";
      mockLocation.search = "?code=COUPON";

      mockStorage.getItem.mockImplementation((key: string) => {
        if (key === "cognito_oauth_in_progress") return Promise.resolve("true");
        if (key === "cognito_oauth_state") return Promise.resolve("test-state");
        if (key === "cognito_oauth_pkce")
          return Promise.resolve("test-verifier");
        return Promise.resolve(null);
      });

      const result = await handleCognitoOAuthCallback();

      expect(result).toBeNull();
      expect(mockProcessTokens).not.toHaveBeenCalled();
      // The in-flight flag must NOT be overwritten ("processing") or cleared,
      // otherwise the real callback would be silently ignored later
      expect(mockStorage.setItem).not.toHaveBeenCalledWith(
        "cognito_oauth_in_progress",
        expect.anything()
      );
      expect(mockStorage.removeItem).not.toHaveBeenCalledWith(
        "cognito_oauth_in_progress"
      );
    });

    it("should process the real callback after a non-callback invocation", async () => {
      const storedItems: Record<string, string> = {
        cognito_oauth_in_progress: "true",
        cognito_oauth_state: "test-state",
        cognito_oauth_pkce: "test-verifier",
      };
      mockStorage.getItem.mockImplementation((key: string) =>
        Promise.resolve(storedItems[key] ?? null)
      );
      mockStorage.setItem.mockImplementation((key: string, value: string) => {
        storedItems[key] = value;
        return Promise.resolve();
      });
      mockStorage.removeItem.mockImplementation((key: string) => {
        delete storedItems[key];
        return Promise.resolve();
      });

      // First invocation: non-callback URL while flow is in flight
      mockLocation.href = "https://app.example.com/some-other-page?code=COUPON";
      mockLocation.pathname = "/some-other-page";
      mockLocation.search = "?code=COUPON";

      expect(await handleCognitoOAuthCallback()).toBeNull();
      expect(storedItems["cognito_oauth_in_progress"]).toBe("true");

      // Second invocation: the real Cognito redirect arrives
      mockLocation.href =
        "https://app.example.com/signin-redirect?code=test-code&state=test-state";
      mockLocation.pathname = "/signin-redirect";
      mockLocation.search = "?code=test-code&state=test-state";

      mockFetch.mockResolvedValue({
        ok: true,
        json: async () => ({
          access_token: "mock-access-token",
          id_token: "mock-id-token",
          refresh_token: "mock-refresh-token",
          expires_in: 3600,
          token_type: "Bearer",
        }),
      });

      const processedTokens = {
        accessToken: "mock-access-token",
        idToken: "mock-id-token",
        refreshToken: "mock-refresh-token",
        expireAt: new Date(Date.now() + 3600000),
        username: "test-user",
        authMethod: "REDIRECT" as const,
      };
      mockProcessTokens.mockResolvedValue(processedTokens);

      const result = await handleCognitoOAuthCallback();

      expect(result).toEqual(processedTokens);
      expect(mockProcessTokens).toHaveBeenCalledTimes(1);
      // OAuth state is cleaned up after successful processing
      expect(storedItems["cognito_oauth_in_progress"]).toBeUndefined();
    });

    it("should throw error on OAuth state mismatch", async () => {
      mockStorage.getItem.mockImplementation((key: string) => {
        if (key === "cognito_oauth_in_progress") return Promise.resolve("true");
        if (key === "cognito_oauth_state")
          return Promise.resolve("different-state");
        return Promise.resolve(null);
      });

      await expect(handleCognitoOAuthCallback()).rejects.toThrow(
        "OAuth state mismatch"
      );
      expect(mockProcessTokens).not.toHaveBeenCalled();
    });

    it("should handle token exchange errors", async () => {
      mockStorage.getItem.mockImplementation((key: string) => {
        if (key === "cognito_oauth_in_progress") return Promise.resolve("true");
        if (key === "cognito_oauth_state") return Promise.resolve("test-state");
        if (key === "cognito_oauth_pkce")
          return Promise.resolve("test-verifier");
        return Promise.resolve(null);
      });

      mockFetch.mockResolvedValue({
        ok: false,
        status: 400,
        json: async () => ({ error: "invalid_grant" }),
      });

      await expect(handleCognitoOAuthCallback()).rejects.toThrow(
        "invalid_grant"
      );
      expect(mockProcessTokens).not.toHaveBeenCalled();
    });
  });

  describe("OAuth callback URL cleanup", () => {
    const setupCodeFlowState = () => {
      mockStorage.getItem.mockImplementation((key: string) => {
        if (key === "cognito_oauth_in_progress") return Promise.resolve("true");
        if (key === "cognito_oauth_state") return Promise.resolve("test-state");
        if (key === "cognito_oauth_pkce")
          return Promise.resolve("test-verifier");
        return Promise.resolve(null);
      });
    };

    const setupSuccessfulExchange = () => {
      mockFetch.mockResolvedValue({
        ok: true,
        json: async () => ({
          access_token: "mock-access-token",
          id_token: "mock-id-token",
          refresh_token: "mock-refresh-token",
          expires_in: 3600,
          token_type: "Bearer",
        }),
      });
      mockProcessTokens.mockResolvedValue({
        accessToken: "mock-access-token",
        idToken: "mock-id-token",
        refreshToken: "mock-refresh-token",
        expireAt: new Date(Date.now() + 3600000),
        username: "test-user",
        authMethod: "REDIRECT" as const,
      });
    };

    it("should scrub code and state via replaceState (not pushState) on success", async () => {
      setupCodeFlowState();
      setupSuccessfulExchange();

      await handleCognitoOAuthCallback();

      expect(mockHistory.replaceState).toHaveBeenCalledWith(
        null,
        "",
        "https://app.example.com/signin-redirect"
      );
      expect(mockHistory.pushState).not.toHaveBeenCalled();
    });

    it("should preserve unrelated query parameters when scrubbing", async () => {
      mockLocation.href =
        "https://app.example.com/signin-redirect?foo=bar&code=test-code&state=test-state";
      mockLocation.search = "?foo=bar&code=test-code&state=test-state";
      setupCodeFlowState();
      setupSuccessfulExchange();

      await handleCognitoOAuthCallback();

      expect(mockHistory.replaceState).toHaveBeenCalledWith(
        null,
        "",
        "https://app.example.com/signin-redirect?foo=bar"
      );
    });

    it("should scrub code and state from the URL on state mismatch", async () => {
      mockStorage.getItem.mockImplementation((key: string) => {
        if (key === "cognito_oauth_in_progress") return Promise.resolve("true");
        if (key === "cognito_oauth_state")
          return Promise.resolve("different-state");
        return Promise.resolve(null);
      });

      await expect(handleCognitoOAuthCallback()).rejects.toThrow(
        "OAuth state mismatch"
      );

      expect(mockHistory.replaceState).toHaveBeenCalledWith(
        null,
        "",
        "https://app.example.com/signin-redirect"
      );
    });

    it("should scrub code and state from the URL when state validation hits a lock timeout", async () => {
      setupCodeFlowState();
      mockWithStorageLock.mockRejectedValueOnce(
        new LockTimeoutError("test-lock-key", 15000)
      );

      await expect(handleCognitoOAuthCallback()).rejects.toThrow(
        "OAuth operation in progress. Please try again."
      );

      expect(mockHistory.replaceState).toHaveBeenCalledWith(
        null,
        "",
        "https://app.example.com/signin-redirect"
      );
      expect(mockProcessTokens).not.toHaveBeenCalled();
    });

    it("should scrub tokens from the URL hash when processTokens fails in the implicit flow", async () => {
      mockLocation.href =
        "https://app.example.com/signin-redirect#access_token=mock-access-token&id_token=mock-id-token&expires_in=3600&state=test-state";
      mockLocation.hash =
        "#access_token=mock-access-token&id_token=mock-id-token&expires_in=3600&state=test-state";
      mockLocation.search = "";
      mockConfig.hostedUi!.responseType = "token";

      mockStorage.getItem.mockImplementation((key: string) => {
        if (key === "cognito_oauth_in_progress") return Promise.resolve("true");
        if (key === "cognito_oauth_state") return Promise.resolve("test-state");
        return Promise.resolve(null);
      });
      mockProcessTokens.mockRejectedValue(
        new Error("token processing failed")
      );

      await expect(handleCognitoOAuthCallback()).rejects.toThrow(
        "token processing failed"
      );

      expect(mockHistory.replaceState).toHaveBeenCalledWith(
        null,
        "",
        "https://app.example.com/signin-redirect"
      );
    });

    it("should scrub the code from the URL when the authorization code is missing", async () => {
      mockLocation.href =
        "https://app.example.com/signin-redirect?state=test-state";
      mockLocation.search = "?state=test-state";
      setupCodeFlowState();

      await expect(handleCognitoOAuthCallback()).rejects.toThrow(
        "Authorization code missing"
      );

      expect(mockHistory.replaceState).toHaveBeenCalledWith(
        null,
        "",
        "https://app.example.com/signin-redirect"
      );
    });

    it("should scrub the code from the URL when the token exchange fails", async () => {
      setupCodeFlowState();
      mockFetch.mockResolvedValue({
        ok: false,
        status: 400,
        json: async () => ({ error: "invalid_grant" }),
      });

      await expect(handleCognitoOAuthCallback()).rejects.toThrow(
        "invalid_grant"
      );

      expect(mockHistory.replaceState).toHaveBeenCalledWith(
        null,
        "",
        "https://app.example.com/signin-redirect"
      );
    });

    it("should scrub the code from the URL on token exchange network errors", async () => {
      setupCodeFlowState();
      mockFetch.mockRejectedValue(new Error("network down"));

      await expect(handleCognitoOAuthCallback()).rejects.toThrow(
        "network down"
      );

      expect(mockHistory.replaceState).toHaveBeenCalledWith(
        null,
        "",
        "https://app.example.com/signin-redirect"
      );
    });

    it("should scrub tokens from the URL hash in the implicit flow", async () => {
      mockLocation.href =
        "https://app.example.com/signin-redirect#access_token=mock-access-token&id_token=mock-id-token&expires_in=3600&state=test-state";
      mockLocation.hash =
        "#access_token=mock-access-token&id_token=mock-id-token&expires_in=3600&state=test-state";
      mockLocation.search = "";
      mockConfig.hostedUi!.responseType = "token";

      mockStorage.getItem.mockImplementation((key: string) => {
        if (key === "cognito_oauth_in_progress") return Promise.resolve("true");
        if (key === "cognito_oauth_state") return Promise.resolve("test-state");
        return Promise.resolve(null);
      });
      mockProcessTokens.mockResolvedValue({
        accessToken: "mock-access-token",
        idToken: "mock-id-token",
        refreshToken: "",
        expireAt: new Date(Date.now() + 3600000),
        username: "test-user",
        authMethod: "REDIRECT" as const,
      });

      await handleCognitoOAuthCallback();

      expect(mockHistory.replaceState).toHaveBeenCalledWith(
        null,
        "",
        "https://app.example.com/signin-redirect"
      );
      expect(mockHistory.pushState).not.toHaveBeenCalled();
    });

    it("should fall back to pushState when replaceState is not provided", async () => {
      // Custom MinimalHistory implementations may not implement replaceState
      const pushOnlyHistory = { pushState: jest.fn() };
      mockConfig.history = pushOnlyHistory as unknown as typeof mockHistory;
      setupCodeFlowState();
      setupSuccessfulExchange();

      await handleCognitoOAuthCallback();

      expect(pushOnlyHistory.pushState).toHaveBeenCalledWith(
        null,
        "",
        "https://app.example.com/signin-redirect"
      );
    });
  });

  describe("customState round-trip", () => {
    // Runs signInWithRedirect and returns the state parameter of the
    // authorize URL that the browser would be redirected to
    const signIn = async (customState?: string) => {
      mockGetAuthorizeEndpoint.mockReturnValue(
        "https://cognito.example.com/oauth2/authorize"
      );
      mockConfig.crypto = webcrypto as unknown as ConfigWithDefaults["crypto"];
      await signInWithRedirect(customState ? { customState } : {});
      const state = new URL(mockLocation.href).searchParams.get("state");
      expect(state).toBeTruthy();
      return state!;
    };

    // Simulates the redirect back from Cognito with the given state
    const runCallback = async (returnedState: string, storedState: string) => {
      mockLocation.href = `https://app.example.com/signin-redirect?code=test-code&state=${encodeURIComponent(
        returnedState
      )}`;
      mockStorage.getItem.mockImplementation((key: string) => {
        if (key === "cognito_oauth_in_progress") return Promise.resolve("true");
        if (key === "cognito_oauth_state") return Promise.resolve(storedState);
        if (key === "cognito_oauth_pkce")
          return Promise.resolve("test-verifier");
        return Promise.resolve(null);
      });
      mockFetch.mockResolvedValue({
        ok: true,
        json: async () => ({
          access_token: "mock-access-token",
          id_token: "mock-id-token",
          refresh_token: "mock-refresh-token",
          expires_in: 3600,
          token_type: "Bearer",
        }),
      });
      mockProcessTokens.mockImplementation(async (tokens) => tokens);
      return handleCognitoOAuthCallback();
    };

    it("should round-trip non-ASCII customState through sign-in URL and callback", async () => {
      const customState = "café-🎉/path?q=1";
      const state = await signIn(customState);

      // URL-safe: random hex prefix, base64url suffix (no "+", "/" or "=")
      expect(state).toMatch(/^[0-9a-f]{64}-[A-Za-z0-9_-]+$/);

      // The exact same state must have been stored for later validation
      expect(mockStorage.setItem).toHaveBeenCalledWith(
        "cognito_oauth_state",
        state
      );

      const result = await runCallback(state, state);
      expect(result).not.toBeNull();
      expect(result?.customState).toBe(customState);
    });

    it("should reject a mismatched random prefix even when customState matches", async () => {
      const state = await signIn("café-🎉/path?q=1");
      const forgedState = "a".repeat(64) + state.slice(state.indexOf("-"));

      await expect(runCallback(forgedState, state)).rejects.toThrow(
        "OAuth state mismatch"
      );
      expect(mockProcessTokens).not.toHaveBeenCalled();
    });

    it("should leave customState undefined when signing in without customState", async () => {
      const state = await signIn();
      expect(state).toMatch(/^[0-9a-f]{64}$/);

      const result = await runCallback(state, state);
      expect(result).not.toBeNull();
      expect(result?.customState).toBeUndefined();
    });
  });

  describe("processTokens integration", () => {
    it("should ensure processTokens handles storage, refresh scheduling, and callbacks", async () => {
      mockStorage.getItem.mockImplementation((key: string) => {
        if (key === "cognito_oauth_in_progress") return Promise.resolve("true");
        if (key === "cognito_oauth_state") return Promise.resolve("test-state");
        if (key === "cognito_oauth_pkce")
          return Promise.resolve("test-verifier");
        return Promise.resolve(null);
      });

      const mockTokenResponse = {
        access_token: "mock-access-token",
        id_token: "mock-id-token",
        refresh_token: "mock-refresh-token",
        expires_in: 3600,
        token_type: "Bearer",
      };

      mockFetch.mockResolvedValue({
        ok: true,
        json: async () => mockTokenResponse,
      });

      // Mock processTokens to simulate its behavior
      mockProcessTokens.mockImplementation(async (tokens) => {
        // Simulate processTokens behavior:
        // 1. Store tokens
        // 2. Schedule refresh
        // 3. Handle device keys
        // 4. Return processed tokens
        return {
          ...tokens,
          // processTokens might add or modify fields
          deviceKey: "mock-device-key",
        };
      });

      const result = await handleCognitoOAuthCallback();

      // Verify processTokens was called
      expect(mockProcessTokens).toHaveBeenCalled();

      // Verify the result includes processTokens enhancements
      expect(result).toHaveProperty("deviceKey", "mock-device-key");
    });
  });
});
