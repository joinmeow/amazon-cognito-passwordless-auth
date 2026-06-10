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
import { useAwaitableState } from "../react/hooks.js";

describe("useAwaitableState", () => {
  test("resolve() settles the awaitable with the current state", async () => {
    const { result } = renderHook(() => useAwaitableState("mfa-code"));

    const promise = result.current.awaitable();
    act(() => result.current.resolve());

    await expect(promise).resolves.toBe("mfa-code");
    expect(result.current.awaited).toEqual({ value: "mfa-code" });
  });

  test("resolve() still settles the awaitable under React StrictMode (double mount)", async () => {
    // StrictMode mounts, unmounts and remounts components in dev. Refs
    // survive the simulated remount, so the unmount cleanup must not leave
    // the hook permanently marked as unmounted (which would make
    // resolve()/reject() no-ops and hang every MFA/new-password prompt).
    const { result } = renderHook(() => useAwaitableState("mfa-code"), {
      wrapper: React.StrictMode,
    });

    const promise = result.current.awaitable();
    act(() => result.current.resolve());

    await expect(promise).resolves.toBe("mfa-code");
    expect(result.current.awaited).toEqual({ value: "mfa-code" });
  });

  test("reject() still settles the awaitable under React StrictMode (double mount)", async () => {
    const { result } = renderHook(() => useAwaitableState("mfa-code"), {
      wrapper: React.StrictMode,
    });

    const promise = result.current.awaitable();
    const caught = promise.catch((err: Error) => err);
    act(() => result.current.reject(new Error("user cancelled")));

    await expect(caught).resolves.toEqual(new Error("user cancelled"));
  });

  test("resolve() is a no-op after a real unmount", () => {
    const { result, unmount } = renderHook(() => useAwaitableState("value"));

    const { resolve } = result.current;
    unmount();

    expect(() => resolve()).not.toThrow();
  });
});
