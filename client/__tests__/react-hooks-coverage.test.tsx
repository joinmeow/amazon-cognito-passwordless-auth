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

import React from "react";
import { render, screen } from "@testing-library/react";
import { renderHook, act } from "@testing-library/react";
import {
  PasswordlessContextProvider,
  usePasswordless,
} from "../react/hooks.js";
import { configure } from "../config.js";
import { retrieveTokens } from "../storage.js";
import { handleCognitoOAuthCallback } from "../hosted-oauth.js";
import {
  prepareFido2SignIn as prepareFido2SignInCore,
  authenticateWithFido2 as authenticateWithFido2Core,
} from "../fido2.js";
import type { PreparedFido2SignIn } from "../fido2.js";

// Mocks
jest.mock("../config");
jest.mock("../storage");
jest.mock("../hosted-oauth");
jest.mock("../fido2", () => {
  const actual = jest.requireActual("../fido2");
  return {
    ...actual,
    authenticateWithFido2: jest.fn(() => ({
      signedIn: Promise.resolve({
        accessToken: "mock",
        idToken: "mock",
        refreshToken: "mock",
        expireAt: new Date(Date.now() + 60_000),
        username: "user",
        authMethod: "FIDO2",
      }),
      abort: jest.fn(),
    })),
    prepareFido2SignIn: jest.fn(),
  };
});

const mockConfigure = configure as jest.MockedFunction<typeof configure>;
const mockRetrieveTokens = retrieveTokens as jest.MockedFunction<
  typeof retrieveTokens
>;
const mockHandleOAuth = handleCognitoOAuthCallback as jest.MockedFunction<
  typeof handleCognitoOAuthCallback
>;
const mockPrepareFido2SignIn = prepareFido2SignInCore as jest.MockedFunction<
  typeof prepareFido2SignInCore
>;
const mockAuthenticateWithFido2 =
  authenticateWithFido2Core as jest.MockedFunction<
    typeof authenticateWithFido2Core
  >;

// Helper wrapper to mount the hook with the provider
const makeWrapper = () =>
  function Wrapper({ children }: { children: React.ReactNode }) {
    return (
      <PasswordlessContextProvider>{children}</PasswordlessContextProvider>
    );
  };

describe("React hooks coverage for hooks.tsx branches", () => {
  beforeEach(() => {
    jest.clearAllMocks();
    mockPrepareFido2SignIn.mockReset();
    mockAuthenticateWithFido2.mockClear();

    // Minimal default config for tests
    mockConfigure.mockReturnValue({
      clientId: "test-client-id",
      debug: jest.fn(),
      storage: {
        getItem: jest.fn(),
        setItem: jest.fn(),
        removeItem: jest.fn(),
      },
    } as unknown as ReturnType<typeof configure>);

    // By default, no cached tokens
    mockRetrieveTokens.mockResolvedValue(undefined);
  });

  it("synthesizes idToken for REDIRECT tokens missing idToken", async () => {
    const future = new Date(Date.now() + 60_000);
    mockRetrieveTokens.mockResolvedValue({
      accessToken: "mock-access-token", // handled by parseJwtPayload mock in setup.ts
      idToken: undefined,
      refreshToken: "mock-refresh-token",
      expireAt: future,
      username: "test-user",
      authMethod: "REDIRECT",
    });

    const wrapper = makeWrapper();
    const { result } = renderHook(() => usePasswordless(), { wrapper });

    // Wait a tick for effects to run
    await act(async () => {
      await new Promise((r) => setTimeout(r, 0));
    });

    // Overall sign-in state should be signed in
    expect(result.current.signInStatus).toBe("SIGNED_IN");

    // tokensParsed should be derived even without original idToken
    expect(result.current.tokensParsed).toBeDefined();
    expect(result.current.tokensParsed?.expireAt).toBeInstanceOf(Date);
    // Access token parsing path covered by existence
    expect(result.current.tokensParsed?.accessToken).toBeDefined();
    expect(result.current.tokensParsed?.idToken).toBeDefined();
  });

  it("processes OAuth callback when code present in URL and updates status", async () => {
    // Ensure no tokens initially so effect proceeds
    mockRetrieveTokens.mockResolvedValue(undefined);

    // Mock OAuth callback handler to return processed tokens
    const processed = {
      accessToken: "mock-access-token",
      idToken: "mock-id-token",
      refreshToken: "mock-refresh-token",
      expireAt: new Date(Date.now() + 3600_000),
      username: "test-user",
      authMethod: "REDIRECT" as const,
    };
    mockHandleOAuth.mockResolvedValue(processed);

    // Mock window.location to include an OAuth code
    const originalHref = globalThis.location?.href || "";
    globalThis.history?.replaceState?.({}, "", "?code=abc&state=xyz");

    const wrapper = makeWrapper();
    const { result } = renderHook(() => usePasswordless(), { wrapper });

    // Await effect to run and resolve
    await act(async () => {
      await new Promise((r) => setTimeout(r, 0));
    });

    expect(mockHandleOAuth).toHaveBeenCalled();
    expect(result.current.signInStatus).toBe("SIGNED_IN");
    expect(result.current.tokens?.accessToken).toBe("mock-access-token");

    // Restore original location
    globalThis.history?.replaceState?.({}, "", originalHref);
  });

  it("renders error fallback via PasswordlessErrorBoundary when child throws", async () => {
    const debugSpy = jest.fn();
    mockConfigure.mockReturnValue({
      clientId: "test-client-id",
      debug: debugSpy,
      storage: {
        getItem: jest.fn(),
        setItem: jest.fn(),
        removeItem: jest.fn(),
      },
    } as unknown as ReturnType<typeof configure>);

    const Boom = () => {
      throw new Error("Boom!");
    };

    render(
      <PasswordlessContextProvider
        errorFallback={<div data-testid="fallback">oops</div>}
      >
        <Boom />
      </PasswordlessContextProvider>
    );

    const el = await screen.findByTestId("fallback");
    expect(el).toBeTruthy();
    // componentDidCatch should log via debug
    expect(debugSpy).toHaveBeenCalled();
  });

  it("logs when markUserActive is called but activity tracking disabled", async () => {
    const debugSpy = jest.fn();
    mockConfigure.mockReturnValue({
      clientId: "test-client-id",
      debug: debugSpy,
      storage: {
        getItem: jest.fn(),
        setItem: jest.fn(),
        removeItem: jest.fn(),
      },
      // No tokenRefresh.useActivityTracking → defaults to disabled
    } as unknown as ReturnType<typeof configure>);

    const wrapper = makeWrapper();
    const { result } = renderHook(() => usePasswordless(), { wrapper });

    act(() => {
      result.current.markUserActive();
    });

    expect(debugSpy).toHaveBeenCalledWith(
      "markUserActive called but activity tracking is disabled"
    );
  });

  it("exposes prepareFido2SignIn passthrough", async () => {
    const prepared: PreparedFido2SignIn = {
      username: "alice",
      session: "mock-session",
      credential: {
        credentialIdB64: "cred",
        authenticatorDataB64: "auth",
        clientDataJSON_B64: "client",
        signatureB64: "sig",
        userHandleB64: "user",
      },
      existingDeviceKey: "device",
    };

    mockPrepareFido2SignIn.mockResolvedValueOnce(prepared);

    const wrapper = makeWrapper();
    const { result } = renderHook(() => usePasswordless(), { wrapper });

    await expect(
      result.current.prepareFido2SignIn({ username: "alice" })
    ).resolves.toBe(prepared);

    expect(mockPrepareFido2SignIn).toHaveBeenCalledWith({
      username: "alice",
      credentials: undefined,
      mediation: undefined,
      signal: undefined,
    });
  });

  it("forwards prepared bundle to authenticateWithFido2", async () => {
    const prepared: PreparedFido2SignIn = {
      username: "charlie",
      session: "session-123",
      credential: {
        credentialIdB64: "cred",
        authenticatorDataB64: "auth",
        clientDataJSON_B64: "client",
        signatureB64: "sig",
        userHandleB64: "user",
      },
      existingDeviceKey: undefined,
    };

    const resolvedTokens = {
      accessToken: "access",
      idToken: "id",
      refreshToken: "refresh",
      expireAt: new Date(Date.now() + 5_000),
      username: "charlie",
      authMethod: "FIDO2" as const,
    };

    mockAuthenticateWithFido2.mockReturnValueOnce({
      signedIn: Promise.resolve(resolvedTokens),
      abort: jest.fn(),
    });

    const wrapper = makeWrapper();
    const { result } = renderHook(() => usePasswordless(), { wrapper });

    const response = result.current.authenticateWithFido2({ prepared });

    expect(mockAuthenticateWithFido2).toHaveBeenCalledWith(
      expect.objectContaining({
        prepared,
        statusCb: expect.any(Function),
        tokensCb: expect.any(Function),
      })
    );

    await expect(response.signedIn).resolves.toEqual(resolvedTokens);
  });
});
