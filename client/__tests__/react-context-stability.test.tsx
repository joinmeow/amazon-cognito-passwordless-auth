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

// Regression test: with tokenRefresh.useActivityTracking enabled, the
// PasswordlessContextProvider used to dispatch a "now tick" every second,
// changing the context value identity and re-rendering every
// usePasswordless() consumer once per second — even consumers that never
// read the activity fields.

import React from "react";
import { render, act } from "@testing-library/react";
import {
  PasswordlessContextProvider,
  usePasswordless,
} from "../react/hooks.js";
import { configure } from "../config.js";
import { retrieveTokens } from "../storage.js";

// Mocks
jest.mock("../config");
jest.mock("../storage");

const mockConfigure = configure as jest.MockedFunction<typeof configure>;
const mockRetrieveTokens = retrieveTokens as jest.MockedFunction<
  typeof retrieveTokens
>;

describe("PasswordlessContext stability with activity tracking enabled", () => {
  beforeEach(() => {
    jest.clearAllMocks();
    jest.useFakeTimers();

    mockConfigure.mockReturnValue({
      clientId: "test-client-id",
      debug: jest.fn(),
      storage: {
        getItem: jest.fn(),
        setItem: jest.fn(),
        removeItem: jest.fn(),
      },
      tokenRefresh: {
        useActivityTracking: true,
      },
    } as unknown as ReturnType<typeof configure>);

    // No cached tokens
    mockRetrieveTokens.mockResolvedValue(undefined);
  });

  afterEach(() => {
    jest.useRealTimers();
  });

  it("does not re-render consumers that ignore activity fields as time passes", async () => {
    let renderCount = 0;
    function Consumer() {
      renderCount++;
      // Reads non-activity fields only
      const { signInStatus, busy } = usePasswordless();
      return (
        <div data-testid="consumer">
          {signInStatus}:{String(busy)}
        </div>
      );
    }

    render(
      <PasswordlessContextProvider>
        <Consumer />
      </PasswordlessContextProvider>
    );

    // Let the initial mount effects (token retrieval etc.) settle
    await act(async () => {
      await Promise.resolve();
    });

    const renderCountAfterMount = renderCount;
    expect(renderCountAfterMount).toBeGreaterThan(0);

    // Advance 5 seconds — on unfixed code the per-second now-tick changed the
    // context value identity, re-rendering the consumer
    await act(async () => {
      jest.advanceTimersByTime(5000);
    });

    expect(renderCount).toBe(renderCountAfterMount);
  });

  it("getTimeSinceLastActivityMs returns a live value without re-rendering", async () => {
    let ctx: ReturnType<typeof usePasswordless> | undefined;
    function Grabber() {
      ctx = usePasswordless();
      return null;
    }

    render(
      <PasswordlessContextProvider>
        <Grabber />
      </PasswordlessContextProvider>
    );
    await act(async () => {
      await Promise.resolve();
    });

    expect(ctx).toBeDefined();
    const before = ctx!.getTimeSinceLastActivityMs();

    await act(async () => {
      jest.advanceTimersByTime(5000);
    });

    // Live value advanced by 5s, read on demand from the same context value
    expect(ctx!.getTimeSinceLastActivityMs()).toBeGreaterThanOrEqual(
      before + 5000
    );

    // markUserActive resets the activity clock (again without re-rendering)
    act(() => {
      ctx!.markUserActive();
    });
    expect(ctx!.getTimeSinceLastActivityMs()).toBeLessThan(5000);
  });

  it("documented activity fields read live and reflect markUserActive() resets", async () => {
    // Regression test for the documented timeSinceLastActivityMs /
    // timeSinceLastActivitySeconds fields: they are getter properties backed
    // by a ref, so an idle-timer component re-rendering (e.g. from its own
    // state update after a user action) reads fresh values — without the
    // provider churning the context value every second.
    let renderCount = 0;
    let ctx: ReturnType<typeof usePasswordless> | undefined;
    let bump: (() => void) | undefined;
    function IdleTimer() {
      renderCount++;
      ctx = usePasswordless();
      const [, forceRender] = React.useReducer((x: number) => x + 1, 0);
      bump = forceRender;
      return (
        <div data-testid="idle-ms">{String(ctx.timeSinceLastActivityMs)}</div>
      );
    }

    const { getByTestId } = render(
      <PasswordlessContextProvider>
        <IdleTimer />
      </PasswordlessContextProvider>
    );
    await act(async () => {
      await Promise.resolve();
    });

    const renderCountAfterMount = renderCount;

    // One minute of idle time — no re-render must occur (the PR's invariant)
    await act(async () => {
      jest.advanceTimersByTime(60_000);
    });
    expect(renderCount).toBe(renderCountAfterMount);

    // A consumer re-render (local state update) now sees the idle time,
    // even though the context value identity did not change
    act(() => {
      bump!();
    });
    expect(Number(getByTestId("idle-ms").textContent)).toBeGreaterThanOrEqual(
      60_000
    );
    expect(ctx!.timeSinceLastActivitySeconds).toBeGreaterThanOrEqual(60);

    // markUserActive() resets the clock; the next consumer re-render (the
    // user action's own state update) reads the reset through the same fields
    act(() => {
      ctx!.markUserActive();
      bump!();
    });
    expect(Number(getByTestId("idle-ms").textContent)).toBeLessThan(60_000);
    expect(ctx!.timeSinceLastActivityMs).toBeLessThan(60_000);
    expect(ctx!.timeSinceLastActivitySeconds).toBeLessThan(60);
  });

  it("propagates a configure() change to useActivityTracking on the next render", async () => {
    let ctx: ReturnType<typeof usePasswordless> | undefined;
    function Grabber() {
      ctx = usePasswordless();
      return null;
    }

    const { rerender } = render(
      <PasswordlessContextProvider>
        <Grabber />
      </PasswordlessContextProvider>
    );
    await act(async () => {
      await Promise.resolve();
    });

    // Activity tracking enabled: fields are numbers
    expect(ctx!.timeSinceLastActivityMs).not.toBeNull();
    expect(ctx!.timeSinceLastActivitySeconds).not.toBeNull();

    // Disable activity tracking via configure()
    mockConfigure.mockReturnValue({
      clientId: "test-client-id",
      debug: jest.fn(),
      storage: {
        getItem: jest.fn(),
        setItem: jest.fn(),
        removeItem: jest.fn(),
      },
      tokenRefresh: {
        useActivityTracking: false,
      },
    } as unknown as ReturnType<typeof configure>);

    // Any subsequent render must propagate the new flag to consumers
    // (the provider's context memo depends on it)
    rerender(
      <PasswordlessContextProvider>
        <Grabber />
      </PasswordlessContextProvider>
    );

    expect(ctx!.timeSinceLastActivityMs).toBeNull();
    expect(ctx!.timeSinceLastActivitySeconds).toBeNull();
    expect(ctx!.getTimeSinceLastActivityMs()).toBe(0);
  });
});
