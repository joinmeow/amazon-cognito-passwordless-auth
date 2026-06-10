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
import { createFetchWithRetry } from "../retry.js";
import type { MinimalResponse } from "../config.js";

describe("createFetchWithRetry", () => {
  const okResponse: MinimalResponse = {
    ok: true,
    status: 200,
    json: () => Promise.resolve({}),
  };

  test("removes abort listener when backoff wait completes normally", async () => {
    const controller = new AbortController();
    const addSpy = jest.spyOn(controller.signal, "addEventListener");
    const removeSpy = jest.spyOn(controller.signal, "removeEventListener");

    // Fail twice with a network error, then succeed: two backoff waits
    let calls = 0;
    const fetchFn = jest.fn().mockImplementation(() => {
      calls++;
      if (calls <= 2) {
        return Promise.reject(new Error("NetworkError"));
      }
      return Promise.resolve(okResponse);
    });

    const fetchWithRetry = createFetchWithRetry(fetchFn, undefined, 3, 1);
    const res = await fetchWithRetry("https://example.com", {
      signal: controller.signal,
    });

    expect(res).toBe(okResponse);
    expect(fetchFn).toHaveBeenCalledTimes(3);

    // Every "abort" listener added during a backoff wait must be removed
    // again once the timer fires, so a long-lived signal doesn't
    // accumulate dead listeners across retries.
    const abortAdds = addSpy.mock.calls.filter(([type]) => type === "abort");
    const abortRemoves = removeSpy.mock.calls.filter(
      ([type]) => type === "abort"
    );
    expect(abortAdds.length).toBe(2);
    expect(abortRemoves.length).toBe(abortAdds.length);
  });

  test("abort during backoff wait still rejects with AbortError", async () => {
    const controller = new AbortController();

    const fetchFn = jest
      .fn()
      .mockImplementation(() => Promise.reject(new Error("NetworkError")));

    // Long backoff so we can abort mid-wait
    const fetchWithRetry = createFetchWithRetry(fetchFn, undefined, 3, 60000);
    const pending = fetchWithRetry("https://example.com", {
      signal: controller.signal,
    });
    const assertion = expect(pending).rejects.toThrow("Aborted");

    // Let the first attempt fail and the backoff wait start, then abort
    await new Promise((resolve) => setTimeout(resolve, 10));
    controller.abort();

    await assertion;
    expect(fetchFn).toHaveBeenCalledTimes(1);
  });
});
