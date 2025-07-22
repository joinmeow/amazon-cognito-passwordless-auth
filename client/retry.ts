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
  baseDelayMs = 1000
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
            let retryErrorType: string | undefined;
            try {
              const cloned = nativeRes.clone();
              const errObj = (await cloned.json()) as { __type?: string };
              const errorType = errObj.__type;
              if (errorType && retryableErrors.has(errorType)) {
                retryErrorType = errorType; // mark for retry after we leave the try/catch
              }
            } catch (parseError) {
              debugFn?.(
                "Failed to parse error response for retryable type:",
                parseError
              );
            }
            // Evaluate retry after JSON parse to avoid the thrown error being
            // swallowed by the try/catch above.
            if (retryErrorType) {
              if (attempt === maxRetries) {
                // On the last attempt, surface the response (like we do for 5xx)
                return res;
              }
              // Throw to trigger retry logic outside of the nested try/catch
              throw new Error(retryErrorType);
            }
          }
          return res;
        }
        // Retry on server errors (5xx), status 0 (network error), or undefined status
        const status = res.status;
        if (status === undefined || status === 0 || status >= 500) {
          if (attempt === maxRetries) {
            // Final attempt: return response so caller can parse error body
            return res;
          }
          // Retry on transient server or network error
          throw new Error(`ServerError:${status}`);
        }
        return res;
      } catch (error: unknown) {
        if (
          init?.signal?.aborted ||
          (error instanceof Error && error.name === "AbortError")
        ) {
          throw error;
        }
        if (attempt === maxRetries) {
          throw error;
        }
        debugFn?.(
          `fetchWithRetry attempt ${attempt}/${maxRetries} failed:`,
          error
        );
        // Exponential backoff for all errors: 1s, 2s, 4s
        const backoff = baseDelayMs * Math.pow(2, attempt - 1);
        debugFn?.(`Retrying in ${backoff}ms...`);
        await wait(backoff);
      }
    }
    // Fallback
    return fetchFn(input, init);
  };
}
