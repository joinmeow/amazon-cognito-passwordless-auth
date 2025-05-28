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
    let attempt = 0;
    while (true) {
      let res: MinimalResponse;
      try {
        res = await fetchFn(input, init);
      } catch (err) {
        // Rethrow immediately on abort
        if ((err as any).name === 'AbortError' || init?.signal?.aborted) {
          throw err;
        }
        // Network error: retry or give up
        attempt++;
        debugFn?.(`fetchWithRetry network error on attempt ${attempt}/${maxRetries} for ${input}`, err);
        if (attempt >= maxRetries) {
          throw err;
        }
        const backoff = baseDelayMs * 2 ** (attempt - 1);
        const jitter = Math.random() * baseDelayMs;
        await new Promise((r) => setTimeout(r, backoff + jitter));
        continue;
      }

      const status = (res as any).status as number | undefined;
      // Return on success or client error
      if (res.ok || (status !== undefined && status >= 400 && status < 500)) {
        return res;
      }
      // Server error: decide to retry or return
      attempt++;
      debugFn?.(`fetchWithRetry HTTP ${status} on attempt ${attempt}/${maxRetries} for ${input}`);
      if (attempt >= maxRetries) {
        // Last attempt: return response so downstream can parse JSON body
        return res;
      }
      const backoff = baseDelayMs * 2 ** (attempt - 1);
      const jitter = Math.random() * baseDelayMs;
      await new Promise((r) => setTimeout(r, backoff + jitter));
    }
  };
} 