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

// Regression test: background token refresh writes tokens to storage from the
// SAME document, and per the WHATWG HTML spec the "storage" event never fires
// in the document that performed the write. The React hook must therefore be
// notified of same-context token stores (via onTokensStored) — otherwise its
// tokens/tokensParsed state stays stale in the active tab until the access
// token expires and the user is bounced to login.

import React from "react";
import { renderHook, act, waitFor } from "@testing-library/react";
import {
  usePasswordless,
  PasswordlessContextProvider,
} from "../react/hooks.js";
import { configure } from "../config.js";
import { storeTokens, onTokensStored } from "../storage.js";
import type { ConfigWithDefaults } from "../config.js";

jest.mock("../config");

const mockConfigure = configure as jest.MockedFunction<typeof configure>;

// Helper to create JWT tokens (header.payload.signature, base64url payload)
const createJWT = (claims: Record<string, unknown>) => {
  const header = btoa(JSON.stringify({ alg: "HS256", typ: "JWT" }))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
  const payload = btoa(JSON.stringify(claims))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
  return `${header}.${payload}.signature`;
};

const username = "test-user";

const makeTokenBundle = (expInSeconds: number, marker: string) => {
  const now = Math.floor(Date.now() / 1000);
  const exp = now + expInSeconds;
  return {
    accessToken: createJWT({
      sub: "test-sub",
      username,
      iat: now,
      exp,
      scope: "aws.cognito.signin.user.admin",
      marker,
    }),
    idToken: createJWT({
      sub: "test-sub",
      "cognito:username": username,
      email: "test@example.com",
      iat: now,
      exp,
      marker,
    }),
    refreshToken: `refresh-token-${marker}`,
    expireAt: new Date(exp * 1000),
    username,
    authMethod: "SRP" as const,
  };
};

describe("Same-tab token store propagation", () => {
  let memoryStorage: Map<string, string>;

  beforeEach(() => {
    memoryStorage = new Map<string, string>();
    const mockConfig: Partial<ConfigWithDefaults> = {
      clientId: "test-client-id",
      debug: undefined,
      storage: {
        getItem: (key: string) => memoryStorage.get(key) ?? null,
        setItem: (key: string, value: string) => {
          memoryStorage.set(key, value);
        },
        removeItem: (key: string) => {
          memoryStorage.delete(key);
        },
      },
    };
    mockConfigure.mockReturnValue(mockConfig as ConfigWithDefaults);
  });

  describe("onTokensStored", () => {
    it("notifies subscribers after storeTokens persists tokens, until unsubscribed", async () => {
      const listener = jest.fn();
      const unsubscribe = onTokensStored(listener);
      try {
        const tokens = makeTokenBundle(3600, "initial");
        await storeTokens(tokens);
        expect(listener).toHaveBeenCalledTimes(1);
        expect(listener).toHaveBeenCalledWith(
          expect.objectContaining({ accessToken: tokens.accessToken })
        );
        // Tokens must already be in storage when the listener fires
        expect(
          memoryStorage.get(
            `CognitoIdentityServiceProvider.test-client-id.${username}.accessToken`
          )
        ).toBe(tokens.accessToken);
      } finally {
        unsubscribe();
      }
      await storeTokens(makeTokenBundle(3600, "after-unsubscribe"));
      expect(listener).toHaveBeenCalledTimes(1);
    });
  });

  describe("usePasswordless", () => {
    const wrapper = ({ children }: { children: React.ReactNode }) => (
      <PasswordlessContextProvider>{children}</PasswordlessContextProvider>
    );

    it("picks up tokens stored by a background refresh in the same tab", async () => {
      // Sign-in state: valid tokens already in storage at mount
      const initialTokens = makeTokenBundle(3600, "initial");
      await storeTokens(initialTokens);

      const { result, unmount } = renderHook(() => usePasswordless(), {
        wrapper,
      });

      await waitFor(() => {
        expect(result.current.tokens?.accessToken).toBe(
          initialTokens.accessToken
        );
      });
      expect(result.current.signInStatus).toBe("SIGNED_IN");

      // Simulate a background refresh: the core refresh machinery persists the
      // refreshed tokens via storeTokens in THIS document. No "storage" event
      // fires for same-document writes, so this is the only signal the hook
      // gets in the active tab.
      const refreshedTokens = makeTokenBundle(7200, "refreshed");
      await act(async () => {
        await storeTokens(refreshedTokens);
      });

      await waitFor(() => {
        expect(result.current.tokens?.accessToken).toBe(
          refreshedTokens.accessToken
        );
      });
      expect(result.current.tokens?.refreshToken).toBe(
        refreshedTokens.refreshToken
      );
      expect(result.current.tokensParsed?.expireAt.valueOf()).toBe(
        refreshedTokens.expireAt.valueOf()
      );
      expect(result.current.signInStatus).toBe("SIGNED_IN");

      unmount();
    });

    it("stops listening for token stores after unmount", async () => {
      const initialTokens = makeTokenBundle(3600, "initial");
      await storeTokens(initialTokens);

      const { result, unmount } = renderHook(() => usePasswordless(), {
        wrapper,
      });
      await waitFor(() => {
        expect(result.current.tokens?.accessToken).toBe(
          initialTokens.accessToken
        );
      });

      unmount();

      // Storing tokens after unmount must not blow up or update unmounted state
      // (React would log a warning / act error if it did)
      await storeTokens(makeTokenBundle(7200, "post-unmount"));
      expect(result.current.tokens?.accessToken).toBe(
        initialTokens.accessToken
      );
    });
  });
});
