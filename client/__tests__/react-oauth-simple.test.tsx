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
import { renderHook, act } from "@testing-library/react";
import {
  usePasswordless,
  PasswordlessContextProvider,
} from "../react/hooks.js";
import { signInWithRedirect } from "../hosted-oauth.js";
import { configure } from "../config.js";
import { retrieveTokens } from "../storage.js";
import type { ConfigWithDefaults } from "../config.js";

// Mock dependencies
jest.mock("../hosted-oauth");
jest.mock("../config");
jest.mock("../storage");

const mockSignInWithRedirect = signInWithRedirect as jest.MockedFunction<
  typeof signInWithRedirect
>;
const mockConfigure = configure as jest.MockedFunction<typeof configure>;
const mockRetrieveTokens = retrieveTokens as jest.MockedFunction<
  typeof retrieveTokens
>;

describe("React OAuth Integration - Simple", () => {
  let mockConfig: Partial<ConfigWithDefaults>;

  beforeEach(() => {
    jest.clearAllMocks();

    mockConfig = {
      clientId: "test-client-id",
      debug: jest.fn(),
      storage: {
        getItem: jest.fn(),
        setItem: jest.fn(),
        removeItem: jest.fn(),
      },
    };

    mockConfigure.mockReturnValue(mockConfig as ConfigWithDefaults);
    mockSignInWithRedirect.mockResolvedValue(undefined);
    mockRetrieveTokens.mockResolvedValue(undefined); // No tokens initially
  });

  const wrapper = ({ children }: { children: React.ReactNode }) => (
    <PasswordlessContextProvider>{children}</PasswordlessContextProvider>
  );

  describe("signInWithRedirect", () => {
    it("should call hosted-oauth signInWithRedirect and update status", async () => {
      const { result } = renderHook(() => usePasswordless(), { wrapper });

      // Wait for initial load to complete
      await act(async () => {
        await new Promise((resolve) => setTimeout(resolve, 100));
      });

      // Initial state should not be signing in
      expect(result.current.signInStatus).not.toBe(
        "STARTING_SIGN_IN_WITH_REDIRECT"
      );

      // Call signInWithRedirect
      act(() => {
        result.current.signInWithRedirect({
          provider: "Google",
        });
      });

      // Should update status - the hook shows SIGNING_IN during the process
      expect(["STARTING_SIGN_IN_WITH_REDIRECT", "SIGNING_IN"]).toContain(
        result.current.signInStatus
      );

      // Should call the hosted-oauth function
      expect(mockSignInWithRedirect).toHaveBeenCalledWith({
        provider: "Google",
      });
    });
  });
});
