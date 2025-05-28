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
import type { MinimalFetch, MinimalResponse } from "./config.js";

/**
 * Return a fetch function that will retry on network errors or HTTP 5xx,
 * up to `maxRetries` times with exponential backoff and jitter.
 */
export function createFetchWithRetry(
  fetchFn: MinimalFetch,
  debugFn?: (...args: unknown[]) => unknown,
  maxRetries = 3,
  baseDelayMs = 100
): MinimalFetch {
  return async (
    input: string | URL,
    init?: {
      signal?: AbortSignal;
      headers?: Record<string, string>;
      method?: string;
      body?: string;
    }
  ): Promise<MinimalResponse> => {
    type ResponseWithStatus = MinimalResponse & { status?: number };
    // Helper to wait with abort support
    const wait = (ms: number): Promise<void> => {
      if (init?.signal?.aborted) {
        return Promise.reject(new DOMException("Aborted", "AbortError"));
      }
      return new Promise((resolve, reject) => {
        const id = setTimeout(resolve, ms);
        init?.signal?.addEventListener(
          "abort",
          () => {
            clearTimeout(id);
            reject(new DOMException("Aborted", "AbortError"));
          },
          { once: true }
        );
      });
    };
    for (let attempt = 1; attempt <= maxRetries; attempt++) {
      // Abort before starting the attempt
      if (init?.signal?.aborted) {
        throw new DOMException("Aborted", "AbortError");
      }
      let res: MinimalResponse;
      try {
        res = await fetchFn(input, init);
      } catch (err: unknown) {
        // Rethrow immediately on abort
        if (
          init?.signal?.aborted ||
          (err instanceof Error && err.name === "AbortError")
        ) {
          throw err;
        }
        // Network error: retry or give up
        debugFn?.(
          `fetchWithRetry network error on attempt ${attempt}/${maxRetries} for ${String(input)}`,
          err
        );
        if (attempt === maxRetries) {
          throw err;
        }
        const backoff = baseDelayMs * 2 ** (attempt - 1);
        const jitter = Math.random() * baseDelayMs;
        await wait(backoff + jitter);
        continue;
      }

      const { status } = res as ResponseWithStatus;
      // Return on success or client error
      if (res.ok || (status !== undefined && status >= 400 && status < 500)) {
        return res;
      }
      // Server error: decide to retry or return
      debugFn?.(
        `fetchWithRetry HTTP ${status} on attempt ${attempt}/${maxRetries} for ${String(input)}`
      );
      if (attempt === maxRetries) {
        // Last attempt: return response so downstream can parse JSON body
        return res;
      }
      const backoff = baseDelayMs * 2 ** (attempt - 1);
      const jitter = Math.random() * baseDelayMs;
      await wait(backoff + jitter);
    }
    // (should never reach here)
    return fetchFn(input, init);
  };
}
