/**
 * Tests for the per-attempt request timeout in createFetchWithRetry.
 *
 * A black-holed connection (no response, no error) must not hang the auth flow
 * forever: each attempt is bounded, a timeout is retried, and a caller-provided
 * signal abort still propagates without being retried.
 */
import {
  createFetchWithRetry,
  FetchAttemptTimeoutError,
  DEFAULT_FETCH_ATTEMPT_TIMEOUT_MS,
} from "../client/retry.js";
import type { MinimalResponse } from "../client/config.js";

const okResponse = { ok: true, status: 200 } as unknown as MinimalResponse;

// A fetch that never settles on its own — it only rejects when its signal is
// aborted, exactly like a real fetch against a black-holed connection.
function blackHoleFetch() {
  return jest.fn(
    (_input: string | URL, init?: { signal?: AbortSignal }) =>
      new Promise<MinimalResponse>((_resolve, reject) => {
        init?.signal?.addEventListener("abort", () =>
          reject(new DOMException("Aborted", "AbortError"))
        );
      })
  );
}

describe("createFetchWithRetry per-attempt timeout", () => {
  beforeEach(() => jest.useFakeTimers());
  afterEach(() => jest.useRealTimers());

  test("has a bounded default timeout", () => {
    expect(DEFAULT_FETCH_ATTEMPT_TIMEOUT_MS).toBeGreaterThan(0);
    expect(DEFAULT_FETCH_ATTEMPT_TIMEOUT_MS).toBeLessThanOrEqual(60000);
  });

  test("a never-settling request times out (does not hang) and throws after retries", async () => {
    const fetchFn = blackHoleFetch();
    const fetchWithRetry = createFetchWithRetry(fetchFn, undefined, 2, 10, 100);

    const promise = fetchWithRetry("https://cognito.example/");
    const settled = promise.catch((e) => e);

    // Attempt 1 times out (100ms) -> backoff (10ms) -> attempt 2 times out.
    await jest.advanceTimersByTimeAsync(100);
    await jest.advanceTimersByTimeAsync(10);
    await jest.advanceTimersByTimeAsync(100);

    const result = await settled;
    expect(result).toBeInstanceOf(FetchAttemptTimeoutError);
    expect(fetchFn).toHaveBeenCalledTimes(2);
  });

  test("a caller abort propagates as AbortError and is not retried", async () => {
    const fetchFn = blackHoleFetch();
    const fetchWithRetry = createFetchWithRetry(fetchFn, undefined, 3, 10, 100);
    const controller = new AbortController();

    const settled = fetchWithRetry("https://cognito.example/", {
      signal: controller.signal,
    }).catch((e: unknown) => e);

    controller.abort();
    await jest.advanceTimersByTimeAsync(0);

    const result = await settled;
    expect((result as Error).name).toBe("AbortError");
    expect(result).not.toBeInstanceOf(FetchAttemptTimeoutError);
    expect(fetchFn).toHaveBeenCalledTimes(1);
  });

  test("a request that settles within the timeout succeeds without retry", async () => {
    const fetchFn = jest.fn(async () => okResponse);
    const fetchWithRetry = createFetchWithRetry(fetchFn, undefined, 3, 10, 100);

    await expect(fetchWithRetry("https://cognito.example/")).resolves.toBe(
      okResponse
    );
    expect(fetchFn).toHaveBeenCalledTimes(1);
  });

  test("a timed-out attempt is retried and can then succeed", async () => {
    let call = 0;
    const fetchFn = jest.fn(
      (_input: string | URL, init?: { signal?: AbortSignal }) => {
        call += 1;
        if (call === 1) {
          return new Promise<MinimalResponse>((_resolve, reject) => {
            init?.signal?.addEventListener("abort", () =>
              reject(new DOMException("Aborted", "AbortError"))
            );
          });
        }
        return Promise.resolve(okResponse);
      }
    );
    const fetchWithRetry = createFetchWithRetry(fetchFn, undefined, 3, 10, 100);

    const settled = fetchWithRetry("https://cognito.example/");

    await jest.advanceTimersByTimeAsync(100); // attempt 1 times out
    await jest.advanceTimersByTimeAsync(10); // backoff, then attempt 2 resolves

    await expect(settled).resolves.toBe(okResponse);
    expect(fetchFn).toHaveBeenCalledTimes(2);
  });

  test("clears the attempt timer on success (no dangling timers)", async () => {
    const fetchFn = jest.fn(async () => okResponse);
    const fetchWithRetry = createFetchWithRetry(fetchFn, undefined, 3, 10, 100);

    await fetchWithRetry("https://cognito.example/");
    expect(jest.getTimerCount()).toBe(0);
  });
});
