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
  constructor(key: string, timeout: number) {
    super(`Timeout acquiring lock '${key}' after ${timeout}ms`);
    this.name = "LockTimeoutError";
  }
}

const DEFAULT_RETRY_DELAY_MS = 50;
const DEFAULT_TIMEOUT_MS = 15000; // 15 seconds to accommodate worst-case refresh (9s) + buffer
const STALE_LOCK_TIMEOUT_MS = 30000; // 30 seconds without a heartbeat renewal
const LOCK_HEARTBEAT_INTERVAL_MS = 10000; // renew held locks well within the stale timeout

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
  let released = false;
  let lockLost = false;
  let heartbeatInFlight: Promise<void> = Promise.resolve();
  const renewLock = async () => {
    try {
      if (released || lockLost) {
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
