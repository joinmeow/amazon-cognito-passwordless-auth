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
 * Per-attempt request timeout. A black-holed connection (TLS established, no
 * response, no error) makes `await fetch` hang forever, which — because auth
 * requests run on the critical sign-in/refresh path — wedges the whole flow
 * (e.g. a hung ConfirmDevice leaves signInStatus stuck "SIGNING_IN" and the
 * app spinning). Bounding each attempt turns a hang into a retryable timeout.
 */
export const DEFAULT_FETCH_ATTEMPT_TIMEOUT_MS = 25000;

/** Thrown when every attempt exceeded `perAttemptTimeoutMs`. */
export class FetchAttemptTimeoutError extends Error {
  constructor(timeoutMs: number) {
    super(`Request timed out after ${timeoutMs}ms`);
    this.name = "FetchAttemptTimeoutError";
  }
}

/**
 * Return a fetch function that will retry on network errors, HTTP 5xx,
 * and specific retryable 400 errors (TooManyRequestsException,
 * LimitExceededException, CodeDeliveryFailureException), up to `maxRetries`
 * times with exponential backoff.
 *
 * Each attempt is bounded by `perAttemptTimeoutMs`: a request that never
 * settles is aborted and retried (or, on the last attempt, surfaced as a
 * `FetchAttemptTimeoutError`) rather than hanging forever. A caller-provided
 * `signal` abort is always propagated and never retried.
 *
 * Uses `Response.clone()` to inspect 400 error bodies without consuming the
 * original response body.
 */
export function createFetchWithRetry(
  fetchFn: MinimalFetch,
  debugFn?: (...args: unknown[]) => unknown,
  maxRetries = 3,
  baseDelayMs = 1000,
  perAttemptTimeoutMs = DEFAULT_FETCH_ATTEMPT_TIMEOUT_MS
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
      const signal = init?.signal;
      if (signal?.aborted) {
        return Promise.reject(new DOMException("Aborted", "AbortError"));
      }
      return new Promise((resolve, reject) => {
        const onAbort = () => {
          clearTimeout(id);
          reject(new DOMException("Aborted", "AbortError"));
        };
        const id = setTimeout(() => {
          signal?.removeEventListener("abort", onAbort);
          resolve();
        }, ms);
        signal?.addEventListener("abort", onAbort, { once: true });
      });
    };

    for (let attempt = 1; attempt <= maxRetries; attempt++) {
      // Abort before starting the attempt
      if (init?.signal?.aborted) {
        throw new DOMException("Aborted", "AbortError");
      }

      // Bound this attempt: abort it if the caller aborts OR the per-attempt
      // timeout fires. A timeout is retryable; a caller abort propagates.
      const attemptController = new AbortController();
      let timedOut = false;
      const onCallerAbort = () => attemptController.abort();
      const callerSignal = init?.signal;
      if (callerSignal) {
        callerSignal.addEventListener("abort", onCallerAbort, { once: true });
      }
      const timeoutId = setTimeout(() => {
        timedOut = true;
        attemptController.abort();
      }, perAttemptTimeoutMs);

      try {
        const res = await fetchFn(input, {
          ...init,
          signal: attemptController.signal,
        });
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
        // A caller-initiated abort always propagates and is never retried.
        if (callerSignal?.aborted) {
          throw error;
        }
        // Our own per-attempt timeout is a transient failure: retry it, or on
        // the last attempt surface a clear timeout instead of a raw AbortError.
        if (timedOut) {
          debugFn?.(
            `fetchWithRetry attempt ${attempt}/${maxRetries} timed out after ${perAttemptTimeoutMs}ms`
          );
          if (attempt === maxRetries) {
            throw new FetchAttemptTimeoutError(perAttemptTimeoutMs);
          }
        } else if (error instanceof Error && error.name === "AbortError") {
          // An AbortError that is neither a caller abort nor our timeout is
          // unexpected; do not silently retry it.
          throw error;
        } else if (attempt === maxRetries) {
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
      } finally {
        clearTimeout(timeoutId);
        callerSignal?.removeEventListener("abort", onCallerAbort);
      }
    }
    // Fallback
    return fetchFn(input, init);
  };
}
