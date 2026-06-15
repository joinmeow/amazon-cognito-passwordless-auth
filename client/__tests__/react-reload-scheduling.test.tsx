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
import { renderHook, waitFor } from "@testing-library/react";
import {
  PasswordlessContextProvider,
  usePasswordless,
} from "../react/hooks.js";
import { configure } from "../config.js";
import { retrieveTokens, onTokensStored, TokensFromStorage } from "../storage.js";
import { scheduleRefresh } from "../refresh.js";

jest.mock("../config");
jest.mock("../storage");
jest.mock("../hosted-oauth");
jest.mock("../refresh");
jest.mock("../fido2", () => {
  const actual = jest.requireActual("../fido2");
  return {
    ...actual,
    fido2ListCredentials: jest.fn(() =>
      Promise.resolve({ authenticators: [] })
    ),
  };
});

const mockConfigure = configure as jest.MockedFunction<typeof configure>;
const mockRetrieveTokens = retrieveTokens as jest.MockedFunction<
  typeof retrieveTokens
>;
const mockOnTokensStored = onTokensStored as jest.MockedFunction<
  typeof onTokensStored
>;
const mockScheduleRefresh = scheduleRefresh as jest.MockedFunction<
  typeof scheduleRefresh
>;

const makeJwt = (payload: Record<string, unknown>) =>
  `eyJhbGciOiJub25lIn0.${btoa(JSON.stringify(payload))}.signature`;

const storedSession = (): TokensFromStorage => {
  const expireAt = new Date(Date.now() + 3600_000);
  return {
    accessToken: makeJwt({
      sub: "s",
      username: "test-user",
      exp: Math.floor(expireAt.valueOf() / 1000),
      iat: Math.floor(Date.now() / 1000),
    }),
    idToken: undefined,
    refreshToken: "stored-refresh-token",
    expireAt,
    username: "test-user",
    authMethod: "SRP",
  };
};

const wrapper = ({ children }: { children: React.ReactNode }) => (
  <PasswordlessContextProvider>{children}</PasswordlessContextProvider>
);

describe("schedule refresh on page reload", () => {
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
    } as unknown as ReturnType<typeof configure>);
    mockOnTokensStored.mockReturnValue(() => {});
    mockScheduleRefresh.mockResolvedValue(undefined);
  });

  it("schedules a refresh on mount when a session is restored from storage", async () => {
    // The page-reload scenario: tokens come from storage, processTokens never
    // runs, so the mount effect must arm the next refresh itself.
    mockRetrieveTokens.mockResolvedValue(storedSession());

    renderHook(() => usePasswordless(), { wrapper });

    await waitFor(() => {
      expect(mockScheduleRefresh).toHaveBeenCalled();
    });
  });

  it("still calls scheduleRefresh when signed out (it self-gates to a no-op)", async () => {
    // Safe to call unconditionally: scheduleRefresh reads storage itself and
    // no-ops when there is no session, so we don't gate on retrieveTokens
    // (which drops an expired-but-refreshable access token).
    mockRetrieveTokens.mockResolvedValue(undefined);

    renderHook(() => usePasswordless(), { wrapper });

    await waitFor(() => {
      expect(mockScheduleRefresh).toHaveBeenCalled();
    });
  });
});
