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
 * and specific retryable 400 errors (TooManyRequestsException, etc.),
 * up to `maxRetries` times with exponential backoff and jitter.
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
    const wait = (ms: number) => new Promise((res) => setTimeout(res, ms));

    for (let attempt = 1; attempt <= maxRetries; attempt++) {
      try {
        const res = await fetchFn(input, init);
        if (res.ok) {
          return res;
        }
        if (res.status === 400) {
          // Parse error response for retryable exception type
          try {
            const errObj = (await res.json()) as { __type?: string };
            const errorType = errObj?.__type;
            if (errorType && retryableErrors.has(errorType)) {
              // Retry on this error type
              throw new Error(errorType);
            }
          } catch (parseError) {
            // If we can't parse the response, don't retry
            debugFn?.("Failed to parse error response:", parseError);
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
