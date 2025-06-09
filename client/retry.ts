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
 * Return a fetch function that will retry on network errors, HTTP 5xx,
 * and specific retryable 400 errors (TooManyRequestsException,
 * LimitExceededException, CodeDeliveryFailureException), up to `maxRetries`
 * times with exponential backoff.
 *
 * Uses `Response.clone()` to inspect 400 error bodies without consuming the
 * original response body.
 */
export function createFetchWithRetry(
  fetchFn: MinimalFetch,
  debugFn?: (...args: unknown[]) => unknown,
  maxRetries = 3,
  baseDelayMs = 100
): MinimalFetch {
  const retryableErrors = new Set([
    "TooManyRequestsException",
    "LimitExceededException",
    "CodeDeliveryFailureException",
  ]);

  return async (
    input: string | URL,
    init?: {
      signal?: AbortSignal;
      headers?: Record<string, string>;
      method?: string;
      body?: string;
    }
  ): Promise<MinimalResponse> => {
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

      try {
        const res = await fetchFn(input, init);
        if (res.ok) {
          return res;
        }
        if (res.status === 400) {
          // Retry on specific 400 errors by cloning the response
          const nativeRes = res as unknown as Response;
          if (typeof nativeRes.clone === "function") {
            try {
              const cloned = nativeRes.clone();
              const errObj = (await cloned.json()) as { __type?: string };
              const errorType = errObj.__type;
              if (errorType && retryableErrors.has(errorType)) {
                // Retry on this error type
                throw new Error(errorType);
              }
            } catch (parseError) {
              debugFn?.(
                "Failed to parse error response for retryable type:",
                parseError
              );
            }
          }
          return res;
        }
        if ((res.status ?? 0) >= 500) {
          throw new Error(`ServerError:${res.status}`);
        }
        return res;
      } catch (err: unknown) {
        if (
          init?.signal?.aborted ||
          (err instanceof Error && err.name === "AbortError")
        ) {
          throw err;
        }
        if (attempt === maxRetries) {
          throw err;
        }
        debugFn?.(
          `fetchWithRetry attempt ${attempt}/${maxRetries} failed:`,
          err
        );
        const backoff = baseDelayMs * 2 ** (attempt - 1);
        await wait(backoff);
      }
    }
    // Fallback
    return fetchFn(input, init);
  };
}
