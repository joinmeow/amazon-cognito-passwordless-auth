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
import { configure } from "./config.js";

/**
 * Custom error class for lock acquisition timeouts
 */
export class LockTimeoutError extends Error {
  /**
   * Type-guard marker. Check this (via isLockTimeoutError) instead of
   * `instanceof`: a bundler can end up with two copies of this module — the
   * app and a dependency each bundling their own — and an instance of one
   * copy's class is not `instanceof` the other copy's.
   */
  readonly isLockTimeout = true;
  constructor(key: string, timeout: number) {
    super(`Timeout acquiring lock '${key}' after ${timeout}ms`);
    this.name = "LockTimeoutError";
  }
}

/**
 * Whether `err` is a lock-acquisition timeout. Use this instead of
 * `instanceof LockTimeoutError` — it stays correct when a bundler has
 * duplicated this module and the error crossed the copy boundary.
 */
export function isLockTimeoutError(err: unknown): err is LockTimeoutError {
  return (
    err instanceof Error &&
    (err as { isLockTimeout?: unknown }).isLockTimeout === true
  );
}

const DEFAULT_RETRY_DELAY_MS = 50;
const STALE_LOCK_TIMEOUT_MS = 30000; // 30 seconds without a heartbeat renewal
// Default acquisition timeout for BOTH backends. Storage backend: it MUST
// exceed the stale threshold (plus a takeover margin) — a lock orphaned by an
// abruptly closed page keeps its last timestamp forever, and a waiter that
// gives up before the orphan CAN go stale is guaranteed a LockTimeoutError;
// worst case the OAuth callback's token exchange right after a redirect, when
// the one-time authorization code is already spent. Web Locks backend: orphans
// don't exist (the browser releases locks on tab death), so this only bounds
// waiting on a LIVE holder — whose longest legitimate critical section (a
// token refresh with retries on a slow network) fits comfortably within it.
const DEFAULT_TIMEOUT_MS = STALE_LOCK_TIMEOUT_MS + 15000;
const LOCK_HEARTBEAT_INTERVAL_MS = 10000; // renew held locks well within the stale timeout
// Stop renewing the heartbeat after this long. A hung critical section
// (e.g. a refresh fetch stuck on a dead connection) must not hold the lock
// forever: once renewals stop, the lock goes stale within
// STALE_LOCK_TIMEOUT_MS and other tabs (e.g. a user signing out) can take
// over. Generous compared to the worst-case legitimate hold (a refresh
// with retries and slow networks is tens of seconds).
const MAX_LOCK_HOLD_MS = 120000;

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

interface LockData {
  id: string;
  timestamp: number;
}

/**
 * Generate a unique lock ID
 */
function generateLockId(): string {
  if (
    typeof globalThis.crypto !== "undefined" &&
    globalThis.crypto.randomUUID
  ) {
    return globalThis.crypto.randomUUID();
  }
  return `${Date.now()}-${Math.random().toString(36).substring(2, 11)}`;
}

/**
 * Parse lock data from storage value
 */
function parseLockData(value: string | null | undefined): LockData | null {
  if (!value) return null;
  try {
    const data = JSON.parse(value) as unknown;
    if (
      data &&
      typeof data === "object" &&
      "id" in data &&
      typeof data.id === "string" &&
      "timestamp" in data &&
      typeof data.timestamp === "number"
    ) {
      return data as LockData;
    }
  } catch {
    // Handle legacy locks
    if (value === "true") {
      return { id: "legacy", timestamp: 0 };
    }
  }
  return null;
}

/**
 * Check if a lock is stale
 */
function isLockStale(lockData: LockData): boolean {
  const age = Date.now() - lockData.timestamp;
  return age > STALE_LOCK_TIMEOUT_MS;
}

/**
 * Simplified storage-based lock without in-process queue
 */
export async function withStorageLock<T>(
  key: string,
  fn: () => Promise<T>,
  timeoutMs = DEFAULT_TIMEOUT_MS,
  abort?: AbortSignal
): Promise<T> {
  const { storage, debug } = configure();
  debug?.("withStorageLock: attempting to acquire lock", key, { timeoutMs });

  // Check for abort signal before starting
  if (abort?.aborted) {
    throw new DOMException("Operation aborted", "AbortError");
  }

  const start = Date.now();
  let lockReleased = false;
  const isBrowser =
    typeof globalThis !== "undefined" &&
    typeof globalThis.addEventListener === "function";
  let onStorage: (e: StorageEvent) => void = () => {};

  // Generate unique lock ID for this attempt
  const lockId = generateLockId();
  const lockData: LockData = {
    id: lockId,
    timestamp: Date.now(),
  };

  // Setup storage event listener for faster lock release detection
  if (isBrowser) {
    onStorage = (e: StorageEvent) => {
      if (e.key !== key) {
        return;
      }
      // Only treat the event as a release when the key was removed or no
      // longer holds a valid, fresh lock. Another waiter acquiring the lock
      // (or a holder renewing its heartbeat) also fires this event and must
      // not be mistaken for a release.
      const newLock = parseLockData(e.newValue);
      if (!newLock || isLockStale(newLock)) {
        debug?.("withStorageLock: storage event detected lock release", key);
        lockReleased = true;
      }
    };
    globalThis.addEventListener("storage", onStorage);
  }

  // Poll until we actually acquired the lock, or timeout
  let acquired = false;
  try {
    let pollDelay = DEFAULT_RETRY_DELAY_MS;
    const maxPollDelay = 500;
    let consecutiveChecks = 0;
    let consecutiveStorageErrors = 0;
    const maxStorageErrors = 3;

    while (!acquired) {
      // Check for abort signal
      if (abort?.aborted) {
        throw new DOMException("Operation aborted", "AbortError");
      }

      try {
        const currentValue = await storage.getItem(key);
        const currentLock = parseLockData(currentValue);

        // Only attempt acquisition if the lock is free, stale, or already
        // ours (the wait may have been cut short by a storage event fired
        // by another waiter acquiring the lock)
        if (
          !currentLock ||
          currentLock.id === lockId ||
          isLockStale(currentLock)
        ) {
          if (currentLock && currentLock.id !== lockId) {
            debug?.("withStorageLock: clearing stale lock", key, {
              lockAge: Date.now() - currentLock.timestamp,
            });
          }
          lockData.timestamp = Date.now();
          await storage.setItem(key, JSON.stringify(lockData));

          // Wait a short randomized jitter before verifying ownership, so
          // that a competing write landing just after ours is detected
          await sleep(5 + Math.floor(Math.random() * 20));

          // Verify we own the lock (handles race condition)
          const verifyValue = await storage.getItem(key);
          const verifyLock = parseLockData(verifyValue);

          if (verifyLock && verifyLock.id === lockId) {
            acquired = true;
            debug?.("withStorageLock: acquired lock", key, {
              lockId,
              elapsedMs: Date.now() - start,
            });
            break;
          }

          // Another contender overwrote our lock; go back to waiting
          debug?.("withStorageLock: lock acquisition race detected", key, {
            ourId: lockId,
            actualId: verifyLock?.id,
          });
        }
        consecutiveStorageErrors = 0;
      } catch (error) {
        debug?.(
          "withStorageLock: storage error during lock acquisition",
          key,
          error
        );
        // Handle storage errors
        consecutiveStorageErrors++;
        if (consecutiveStorageErrors >= maxStorageErrors) {
          throw new Error(
            `Failed to acquire lock due to storage error: ${String(error)}`
          );
        }
      }

      // Check timeout
      if (Date.now() - start > timeoutMs) {
        debug?.("withStorageLock: timeout acquiring lock", key, {
          elapsed: Date.now() - start,
        });
        throw new LockTimeoutError(key, timeoutMs);
      }

      // Adaptive polling: increase delay after several consecutive checks,
      // but go back to fast polling when a storage event hints at a release
      consecutiveChecks++;
      if (lockReleased) {
        lockReleased = false;
        pollDelay = DEFAULT_RETRY_DELAY_MS;
        consecutiveChecks = 0;
      } else if (consecutiveChecks > 3) {
        pollDelay = Math.min(pollDelay * 1.5, maxPollDelay);
      }

      await sleep(pollDelay);
    }
  } finally {
    if (isBrowser) {
      globalThis.removeEventListener("storage", onStorage);
    }
  }

  // Renew the lock's timestamp periodically so that long critical sections
  // (e.g. token refresh with retries on a slow network) are not declared
  // stale and taken over by other tabs. If we ever detect that we no longer
  // (safely) hold the lock, stop renewing for good rather than risk
  // clobbering another tab's legitimate takeover
  const holdStart = Date.now();
  let released = false;
  let lockLost = false;
  let heartbeatInFlight: Promise<void> = Promise.resolve();
  const renewLock = async () => {
    try {
      if (released || lockLost) {
        return;
      }
      if (Date.now() - holdStart > MAX_LOCK_HOLD_MS) {
        // The critical section has been running implausibly long (hung
        // fetch, suspended tab, ...). Stop renewing so the lock can go
        // stale and be taken over; if fn() does eventually finish, release
        // below still removes the lock if it is still ours.
        clearInterval(heartbeat);
        debug?.(
          "withStorageLock: max lock hold time reached, heartbeat stopped so the lock can go stale",
          key,
          { heldMs: Date.now() - holdStart }
        );
        return;
      }
      const currentValue = await storage.getItem(key);
      const currentLock = parseLockData(currentValue);
      if (!currentLock || currentLock.id !== lockId) {
        // The lock vanished or another tab took it over; we no longer hold
        // it, so stop renewing for good — a renewal write now would clobber
        // the new holder and break mutual exclusion
        lockLost = true;
        clearInterval(heartbeat);
        debug?.(
          "withStorageLock: lock lost during critical section, heartbeat stopped",
          key,
          { ourId: lockId, actualId: currentLock?.id }
        );
        return;
      }
      if (isLockStale(currentLock)) {
        // Our own lock went stale before this renewal could land (e.g. timer
        // throttling or slow storage). Another tab is entitled to take over
        // a stale lock at any moment — possibly between the read above and a
        // write below — and our read may even be a delayed snapshot taken
        // before such a takeover. Writing now could overwrite the legitimate
        // new holder, so stand down instead of renewing.
        lockLost = true;
        clearInterval(heartbeat);
        debug?.(
          "withStorageLock: own lock went stale, heartbeat stopped to avoid clobbering a takeover",
          key,
          { ourId: lockId, lockAge: Date.now() - currentLock.timestamp }
        );
        return;
      }
      lockData.timestamp = Date.now();
      // The critical section may have finished (and the lock been removed,
      // possibly even acquired by another tab already) while we awaited the
      // read above; writing now would resurrect the released lock and block
      // other tabs until it goes stale. This check must remain immediately
      // before the write, with no awaits in between.
      if (released) {
        return;
      }
      await storage.setItem(key, JSON.stringify(lockData));

      // Post-write verify, mirroring acquisition: wait a short randomized
      // jitter, then re-read to confirm we still own the lock. A contender
      // that judged our pre-write value stale may have written just after
      // us and passed its own verify; in that case it is the rightful
      // holder now and we must stand down (re-writing would clobber it)
      await sleep(5 + Math.floor(Math.random() * 20));
      const verifyValue = await storage.getItem(key);
      const verifyLock = parseLockData(verifyValue);
      if (!verifyLock || verifyLock.id !== lockId) {
        lockLost = true;
        clearInterval(heartbeat);
        debug?.(
          "withStorageLock: lock taken over during heartbeat renewal, heartbeat stopped",
          key,
          { ourId: lockId, actualId: verifyLock?.id }
        );
      }
    } catch (error) {
      debug?.("withStorageLock: error renewing lock heartbeat", key, error);
    }
  };
  const heartbeat = setInterval(() => {
    // Chain renewals so at most one is in flight at a time, and so release
    // below can await the pending one (renewLock never throws)
    heartbeatInFlight = heartbeatInFlight.then(renewLock);
  }, LOCK_HEARTBEAT_INTERVAL_MS);

  try {
    return await fn();
  } finally {
    // Set before any await so an in-flight heartbeat renewal cannot write
    // the lock back after we remove it below
    released = true;
    clearInterval(heartbeat);
    debug?.("withStorageLock: releasing lock", key);
    try {
      // Wait for a pending renewal (if any) to settle, so its write cannot
      // land after our removal
      await heartbeatInFlight;
      // Only remove our lock
      const currentValue = await storage.getItem(key);
      const currentLock = parseLockData(currentValue);

      if (currentLock && currentLock.id === lockId) {
        await storage.removeItem(key);
      } else {
        debug?.(
          "withStorageLock: lock already released or taken by another process",
          key
        );
      }
    } catch (error) {
      // Log but don't throw - the operation succeeded
      debug?.("withStorageLock: error releasing lock", key, error);
    }
  }
}

/**
 * Which cross-tab lock backend withLock will use in this context. Exposed so
 * applications can tag telemetry (e.g. RUM auth events) with the backend in
 * use — stalls have very different failure modes on the two paths (a storage
 * lock can be orphaned by a dead tab; a Web Lock cannot).
 */
export function activeLockBackend(): "web-locks" | "storage" {
  return webLocksAvailable() ? "web-locks" : "storage";
}

/**
 * Internal sentinel: navigator.locks exists but request() rejected with
 * SecurityError BEFORE the lock was granted — an opaque origin (e.g. a
 * sandboxed iframe without allow-same-origin) does this. The critical section
 * has NOT run, so withLock can safely retry on the storage backend.
 */
class WebLocksUnusableError extends Error {
  constructor(readonly reason: unknown) {
    super("Web Locks API is unusable in this context");
    this.name = "WebLocksUnusableError";
  }
}

/**
 * Whether the Web Locks API is usable in this context. It requires a secure
 * context (https or localhost); in insecure contexts, Node, SSR, and older
 * browsers `navigator.locks` is absent and we fall back to the storage lock.
 */
function webLocksAvailable(): boolean {
  if (
    typeof globalThis === "undefined" ||
    typeof globalThis.navigator === "undefined"
  ) {
    return false;
  }
  const locks = (globalThis.navigator as { locks?: LockManager }).locks;
  return typeof locks?.request === "function";
}

/**
 * Acquire a cross-tab lock via the Web Locks API and run `fn` while holding it.
 *
 * The critical advantage over the storage lock: the browser owns the lock and
 * releases it automatically when the document unloads or the agent is
 * terminated (a refresh, navigation, tab close, or crash). A tab killed
 * mid-critical-section therefore cannot orphan the lock and stall other tabs
 * for the ~30s stale-takeover window — the failure class behind the login and
 * logout stalls.
 *
 * `abort` and the acquisition `timeoutMs` bound ACQUISITION only: a pending
 * `navigator.locks.request` is cancelled through its `signal`. Once the lock is
 * held, aborting has no effect (per the Web Locks spec), so a hung critical
 * section must bound itself (e.g. the per-attempt fetch timeout on the
 * refresh/revoke calls).
 */
async function withWebLock<T>(
  key: string,
  fn: () => Promise<T>,
  timeoutMs: number,
  abort?: AbortSignal
): Promise<T> {
  const { debug } = configure();
  if (abort?.aborted) {
    throw new DOMException("Operation aborted", "AbortError");
  }

  if (timeoutMs === 0) {
    // Try-immediate: take the lock only if it is free right now, never queue.
    // The Web Locks spec forbids combining `signal` with `ifAvailable`, so
    // there is no pending wait to interrupt — the caller abort was already
    // checked above, and once granted an abort has no effect anyway.
    let granted = false;
    try {
      return (await globalThis.navigator.locks.request(
        key,
        { mode: "exclusive", ifAvailable: true },
        async (lock) => {
          if (!lock) {
            debug?.("withWebLock: lock unavailable (try-immediate)", key);
            throw new LockTimeoutError(key, 0);
          }
          granted = true;
          debug?.("withWebLock: acquired lock", key);
          return fn();
        }
      )) as T;
    } catch (err) {
      if (
        !granted &&
        err instanceof DOMException &&
        err.name === "SecurityError"
      ) {
        throw new WebLocksUnusableError(err);
      }
      throw err;
    }
  }

  // One controller aborts the pending request on caller-abort OR the
  // acquisition deadline. `timedOut` distinguishes the two so the deadline maps
  // to LockTimeoutError (matching the storage backend's contract) while a
  // caller abort propagates as AbortError. `granted` gates BOTH translations:
  // the deadline can fire in the microtask gap between the browser granting the
  // lock and the callback clearing the timer, and once fn() is running any
  // AbortError it throws is its own (e.g. an aborted fetch inside the critical
  // section) and must propagate unchanged rather than be reported as a lock
  // acquisition failure.
  const acquireController = new AbortController();
  let timedOut = false;
  let granted = false;
  const onCallerAbort = () => acquireController.abort();
  abort?.addEventListener("abort", onCallerAbort, { once: true });
  const acquireTimer = setTimeout(() => {
    timedOut = true;
    acquireController.abort();
  }, timeoutMs);
  const clearAcquireTimer = () => clearTimeout(acquireTimer);

  try {
    // The DOM lib types LockManager.request as Promise<any>; the callback here
    // returns fn()'s result, so the resolved value is T.
    return (await globalThis.navigator.locks.request(
      key,
      { mode: "exclusive", signal: acquireController.signal },
      async () => {
        // Acquired — the acquisition deadline no longer applies to the lock we
        // now hold. The callback promise settling releases the lock, so a
        // throw from fn() still releases it.
        granted = true;
        clearAcquireTimer();
        debug?.("withWebLock: acquired lock", key);
        return fn();
      }
    )) as T;
  } catch (err) {
    if (!granted && err instanceof DOMException) {
      if (err.name === "AbortError") {
        if (timedOut) {
          debug?.("withWebLock: timeout acquiring lock", key, { timeoutMs });
          throw new LockTimeoutError(key, timeoutMs);
        }
        debug?.("withWebLock: acquisition aborted by caller", key);
      } else if (err.name === "SecurityError") {
        // Opaque origin: request() rejects before any grant. fn() has not
        // run — signal withLock to retry on the storage backend.
        throw new WebLocksUnusableError(err);
      }
    }
    throw err;
  } finally {
    clearAcquireTimer();
    abort?.removeEventListener("abort", onCallerAbort);
  }
}

/**
 * Acquire a cross-tab lock and run `fn` while holding it. Uses the Web Locks
 * API when available (browser-owned, auto-released on tab death) and falls back
 * to the storage lock otherwise (Node, SSR, insecure contexts, unsupported
 * browsers). Both backends honor the caller `abort` and surface a
 * `LockTimeoutError` when acquisition exceeds `timeoutMs`.
 *
 * `timeoutMs: 0` means try-immediate: take the lock only if it is free right
 * now, otherwise throw `LockTimeoutError` without queueing (Web Locks:
 * `ifAvailable`; storage: a single acquisition attempt). Use it for
 * best-effort background work that should skip, not wait, when another
 * context is already doing the job.
 *
 * Mixed-version caveat: a tab on the storage lock and a tab on Web Locks do not
 * coordinate on the same key. Safe here because sign-out takes no lock, and a
 * doubly-run refresh is bounded by the lastRefreshAttempt window, the
 * refresh-token-reuse retry, and the sign-out tombstone re-validation.
 */
export async function withLock<T>(
  key: string,
  fn: () => Promise<T>,
  timeoutMs = DEFAULT_TIMEOUT_MS,
  abort?: AbortSignal
): Promise<T> {
  const { debug } = configure();
  if (webLocksAvailable()) {
    debug?.("withLock: acquiring via Web Locks backend", key);
    try {
      return await withWebLock(key, fn, timeoutMs, abort);
    } catch (err) {
      if (!(err instanceof WebLocksUnusableError)) {
        throw err;
      }
      // navigator.locks exists but rejected with SecurityError before any
      // grant (opaque origin) — fn() has not run, so retrying on the storage
      // backend is safe. Note the storage backend may be unusable there too
      // (localStorage throws in sandboxed iframes) unless the app configured
      // a custom storage; either way this surfaces a coherent storage error
      // instead of a baffling SecurityError from a lock API.
      debug?.(
        "withLock: Web Locks unusable in this context; falling back to storage lock",
        key
      );
    }
  }
  debug?.("withLock: acquiring via storage-lock fallback", key);
  return withStorageLock(key, fn, timeoutMs, abort);
}
