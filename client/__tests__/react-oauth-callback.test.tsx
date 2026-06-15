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
import { renderHook, act, waitFor } from "@testing-library/react";
import {
  usePasswordless,
  PasswordlessContextProvider,
} from "../react/hooks.js";
import { handleCognitoOAuthCallback } from "../hosted-oauth.js";
import { configure } from "../config.js";
import { retrieveTokens, onTokensStored } from "../storage.js";
import type { ConfigWithDefaults } from "../config.js";

jest.mock("../hosted-oauth");
jest.mock("../config");
jest.mock("../storage");

const mockHandleCallback = handleCognitoOAuthCallback as jest.MockedFunction<
  typeof handleCognitoOAuthCallback
>;
const mockConfigure = configure as jest.MockedFunction<typeof configure>;
const mockRetrieveTokens = retrieveTokens as jest.MockedFunction<
  typeof retrieveTokens
>;
const mockOnTokensStored = onTokensStored as jest.MockedFunction<
  typeof onTokensStored
>;

// Point globalThis.location at a callback URL with the given query/hash.
// jsdom's location is not configurable, but history.replaceState updates
// location.search / location.hash / location.href in place.
const setLocation = (search: string, hash = "") => {
  globalThis.history.replaceState({}, "", `/signin-redirect${search}${hash}`);
};

const wrapper = ({ children }: { children: React.ReactNode }) => (
  <PasswordlessContextProvider>{children}</PasswordlessContextProvider>
);

describe("React OAuth callback handling", () => {
  beforeEach(() => {
    jest.clearAllMocks();
    mockConfigure.mockReturnValue({
      clientId: "test-client-id",
      debug: jest.fn(),
      storage: {
        getItem: jest.fn(),
        setItem: jest.fn(),
        removeItem: jest.fn(),
      },
    } as unknown as ConfigWithDefaults);
    mockRetrieveTokens.mockResolvedValue(undefined); // not signed in
    mockOnTokensStored.mockReturnValue(() => {});
  });

  afterEach(() => {
    setLocation(""); // reset to a non-callback URL
  });

  it("invokes the callback handler and surfaces the error for an error-only redirect", async () => {
    // The user denied consent: the redirect carries ?error=access_denied with
    // NO code and NO access_token. The handler (which surfaces provider
    // errors) must still be invoked.
    setLocation("?error=access_denied&error_description=User+denied&state=s");
    mockHandleCallback.mockRejectedValue(new Error("User denied"));

    const { result } = renderHook(() => usePasswordless(), { wrapper });

    await waitFor(() => {
      expect(mockHandleCallback).toHaveBeenCalledTimes(1);
    });
    await waitFor(() => {
      expect(result.current.lastError?.message).toBe("User denied");
    });
    expect(result.current.signInStatus).toBe("NOT_SIGNED_IN");
  });

  it("does not stay stuck busy when the callback handler returns null", async () => {
    // The gate fires (a code is present) but the handler returns null — e.g.
    // it wasn't actually our in-progress redirect. The UI must resolve to the
    // real (not-signed-in) state, not stay pinned at SIGNING_IN.
    setLocation("?code=abc&state=s");
    mockHandleCallback.mockResolvedValue(null);

    const { result } = renderHook(() => usePasswordless(), { wrapper });

    await waitFor(() => {
      expect(mockHandleCallback).toHaveBeenCalledTimes(1);
    });
    await waitFor(() => {
      expect(result.current.signInStatus).toBe("NOT_SIGNED_IN");
    });
    expect(result.current.signInStatus).not.toBe("SIGNING_IN");
  });

  it("reaches SIGNED_IN_WITH_REDIRECT when the handler returns tokens", async () => {
    setLocation("?code=abc&state=s");
    mockHandleCallback.mockResolvedValue({
      accessToken: "a",
      idToken: "i",
      refreshToken: "r",
      expireAt: new Date(Date.now() + 3600_000),
      username: "user",
      authMethod: "REDIRECT",
    });

    const { result } = renderHook(() => usePasswordless(), { wrapper });

    await waitFor(() => {
      expect(mockHandleCallback).toHaveBeenCalledTimes(1);
    });
    await waitFor(() => {
      expect(result.current.signInStatus).toBe("SIGNED_IN");
    });
  });

  it("does not invoke the callback handler on a plain (non-callback) URL", async () => {
    setLocation("?foo=bar");
    mockHandleCallback.mockResolvedValue(null);

    renderHook(() => usePasswordless(), { wrapper });
    await act(async () => {
      await new Promise((r) => setTimeout(r, 50));
    });

    expect(mockHandleCallback).not.toHaveBeenCalled();
  });

  it("ignores a fragment-only error in code flow (does not invoke the handler)", async () => {
    // Code flow delivers errors in the query, never the fragment. A stray
    // `#error=…` on the redirect path is not our callback — admitting it would
    // drive the handler to validate state first, find none (code-flow state is
    // in the query), and clear the shared OAuth state (PKCE / state /
    // in-progress), which can abort a real code-flow redirect in another tab.
    setLocation(
      "",
      "#error=access_denied&error_description=User+denied&state=s"
    );
    mockHandleCallback.mockResolvedValue(null);

    renderHook(() => usePasswordless(), { wrapper });
    await act(async () => {
      await new Promise((r) => setTimeout(r, 50));
    });

    expect(mockHandleCallback).not.toHaveBeenCalled();
  });

  it("invokes the handler and surfaces a fragment error in implicit flow", async () => {
    // Implicit flow (responseType "token") legitimately delivers errors in the
    // fragment, so the gate must admit them and the handler must surface them.
    mockConfigure.mockReturnValue({
      clientId: "test-client-id",
      debug: jest.fn(),
      hostedUi: { responseType: "token" },
      storage: {
        getItem: jest.fn(),
        setItem: jest.fn(),
        removeItem: jest.fn(),
      },
    } as unknown as ConfigWithDefaults);
    setLocation(
      "",
      "#error=access_denied&error_description=User+denied&state=s"
    );
    mockHandleCallback.mockRejectedValue(new Error("User denied"));

    const { result } = renderHook(() => usePasswordless(), { wrapper });

    await waitFor(() => {
      expect(mockHandleCallback).toHaveBeenCalledTimes(1);
    });
    await waitFor(() => {
      expect(result.current.lastError?.message).toBe("User denied");
    });
  });
});
