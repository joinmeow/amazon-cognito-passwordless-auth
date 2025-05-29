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

const DEFAULT_RETRY_DELAY_MS = 50;
const DEFAULT_TIMEOUT_MS = 5000;
// Stale lock timeout should be significantly longer than acquisition timeout
// to avoid confusion. A lock is considered stale if held longer than this.
const STALE_LOCK_TIMEOUT_MS = 30000; // 30 seconds - 6x the acquisition timeout

// In-process FIFO lock queue
const inProcessLockMap = new Map<string, Promise<void>>();
const MAX_LOCK_ENTRIES = 100;

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
  // Use crypto.randomUUID if available, fallback to timestamp + random
  if (
    typeof globalThis.crypto !== "undefined" &&
    globalThis.crypto.randomUUID
  ) {
    return globalThis.crypto.randomUUID();
  }
  return `${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
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
    // Handle legacy "true" locks for backward compatibility
    if (value === "true") {
      return { id: "legacy", timestamp: 0 };
    }
  }
  return null;
}

/**
 * Check if a lock is stale based on timestamp
 * A lock is stale if it's older than STALE_LOCK_TIMEOUT_MS
 */
function isLockStale(lockData: LockData): boolean {
  const age = Date.now() - lockData.timestamp;
  return age > STALE_LOCK_TIMEOUT_MS;
}

/**
 * Clean up the in-process lock map if it gets too large
 * This prevents memory leaks in long-running browser sessions
 */
function cleanupLockMapIfNeeded(): void {
  if (inProcessLockMap.size > MAX_LOCK_ENTRIES) {
    const { debug } = configure();
    debug?.(
      `withStorageLock: cleaning up lock map, size was ${inProcessLockMap.size}`
    );
    inProcessLockMap.clear();
  }
}

/**
 * Acquire a simple storage-based lock on `key`, run `fn`, then release the lock.
 * Retries until timeoutMs if lock is already held.
 * Uses an in-process lock to ensure proper ordering within the same tab.
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

  // Clean up lock map if it's getting too large
  cleanupLockMapIfNeeded();

  // Always use in-process FIFO lock to ensure proper ordering
  let releaseInProcess: () => void;
  const previous = inProcessLockMap.get(key) || Promise.resolve();
  const nextLockPromise = new Promise<void>((resolve) => {
    releaseInProcess = resolve;
  });
  inProcessLockMap.set(key, nextLockPromise);

  // Wait for any previous in-process lock holders, but respect timeout
  const startTime = Date.now();
  const timeoutPromise = new Promise<never>((_, reject) => {
    setTimeout(
      () => reject(new Error(`Timeout acquiring lock: ${key}`)),
      timeoutMs
    );
  });

  // Add abort signal to the race if provided
  const promises: Promise<unknown>[] = [previous, timeoutPromise];
  if (abort) {
    promises.push(
      new Promise<never>((_, reject) => {
        abort.addEventListener(
          "abort",
          () => {
            reject(new DOMException("Operation aborted", "AbortError"));
          },
          { once: true }
        );
      })
    );
  }

  try {
    await Promise.race(promises);
  } catch (err) {
    // Clean up on timeout
    releaseInProcess!();
    if (inProcessLockMap.get(key) === nextLockPromise) {
      inProcessLockMap.delete(key);
    }
    throw err;
  }

  // Adjust remaining timeout after waiting in queue
  const elapsedTime = Date.now() - startTime;
  const remainingTimeout = Math.max(0, timeoutMs - elapsedTime);
  if (remainingTimeout === 0) {
    // Clean up if we've already timed out
    releaseInProcess!();
    if (inProcessLockMap.get(key) === nextLockPromise) {
      inProcessLockMap.delete(key);
    }
    throw new Error(`Timeout acquiring lock: ${key}`);
  }

  const start = Date.now();
  let lockReleased = false;
  const isBrowser =
    typeof globalThis !== "undefined" &&
    typeof globalThis.addEventListener === "function";
  let onStorage: (e: StorageEvent) => void = () => {};
  let storageEventTimeout: ReturnType<typeof setTimeout> | undefined;

  // Generate unique lock ID for this attempt
  const lockId = generateLockId();
  const lockData: LockData = {
    id: lockId,
    timestamp: Date.now(),
  };

  if (isBrowser) {
    onStorage = (e: StorageEvent) => {
      if (
        e.key === key &&
        (!e.newValue || e.newValue !== JSON.stringify(lockData))
      ) {
        debug?.("withStorageLock: storage event detected lock release", key);
        lockReleased = true;
        // Clear the fallback timeout since we got the event
        if (storageEventTimeout) {
          clearTimeout(storageEventTimeout);
          storageEventTimeout = undefined;
        }
      }
    };
    globalThis.addEventListener("storage", onStorage);

    // Fallback: periodically check even if storage events are unreliable
    // This ensures we don't get stuck if storage events are missed
    const checkInterval = Math.min(DEFAULT_RETRY_DELAY_MS * 2, 200); // Max 200ms
    storageEventTimeout = setTimeout(function checkStorageFallback() {
      if (!lockReleased) {
        // Force a check by setting lockReleased to trigger the main loop check
        // This is safer than duplicating the lock checking logic here
        debug?.("withStorageLock: storage event fallback check", key);
        storageEventTimeout = setTimeout(checkStorageFallback, checkInterval);
      }
    }, checkInterval);
  }

  try {
    // Spin until storage lock is free, timeout, or notified by storage event
    // Use adaptive polling with exponential backoff to reduce performance impact
    let pollDelay = DEFAULT_RETRY_DELAY_MS;
    const maxPollDelay = 500; // Cap at 500ms
    let consecutiveChecks = 0;

    while (!lockReleased) {
      // Check for abort signal
      if (abort?.aborted) {
        throw new DOMException("Operation aborted", "AbortError");
      }

      const currentValue = await storage.getItem(key);
      const currentLock = parseLockData(currentValue);

      // Check if lock is free or stale
      if (!currentLock || isLockStale(currentLock)) {
        if (currentLock && isLockStale(currentLock)) {
          debug?.("withStorageLock: clearing stale lock", key, {
            lockAge: Date.now() - currentLock.timestamp,
          });
        }
        break; // Lock is available
      }

      // Check timeout
      if (Date.now() - start > remainingTimeout) {
        debug?.("withStorageLock: timeout acquiring lock", key, {
          elapsed: Date.now() - start,
        });
        throw new Error(`Timeout acquiring lock: ${key}`);
      }

      // Adaptive polling: increase delay after several consecutive checks
      consecutiveChecks++;
      if (consecutiveChecks > 3) {
        pollDelay = Math.min(pollDelay * 1.5, maxPollDelay);
      }

      await sleep(pollDelay);
    }
  } finally {
    if (isBrowser) {
      globalThis.removeEventListener("storage", onStorage);
      // Clear any remaining storage event timeout
      if (storageEventTimeout) {
        clearTimeout(storageEventTimeout);
      }
    }
  }

  // Acquire storage lock with atomic check
  let acquired = false;
  const maxAcquisitionAttempts = 3;

  for (let attempt = 1; attempt <= maxAcquisitionAttempts; attempt++) {
    try {
      await storage.setItem(key, JSON.stringify(lockData));

      // Verify we own the lock (handles race condition)
      const verifyValue = await storage.getItem(key);
      const verifyLock = parseLockData(verifyValue);

      if (verifyLock && verifyLock.id === lockId) {
        acquired = true;
        debug?.("withStorageLock: acquired lock", key, {
          lockId,
          attempt,
          elapsedMs: Date.now() - start,
        });
        break;
      } else {
        debug?.("withStorageLock: lock acquisition race detected", key, {
          ourId: lockId,
          actualId: verifyLock?.id,
          attempt,
          elapsedMs: Date.now() - start,
        });

        // Small backoff before retry
        if (attempt < maxAcquisitionAttempts) {
          await sleep(DEFAULT_RETRY_DELAY_MS * attempt);
        }
      }
    } catch (err) {
      debug?.(
        "withStorageLock: storage error during lock acquisition",
        key,
        err
      );
      // Handle storage errors (quota exceeded, disabled storage, etc.)
      if (attempt === maxAcquisitionAttempts) {
        throw new Error(
          `Failed to acquire lock due to storage error: ${String(err)}`
        );
      }
    }
  }

  if (!acquired) {
    throw new Error(
      `Failed to acquire lock after ${maxAcquisitionAttempts} attempts: ${key}`
    );
  }

  try {
    return await fn();
  } finally {
    debug?.("withStorageLock: releasing lock", key);
    try {
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
    } catch (err) {
      // Log but don't throw - the operation succeeded
      debug?.("withStorageLock: error releasing lock", key, err);
    }

    // Release in-process FIFO lock
    releaseInProcess!();
    // Clean up map entry if this was the last in queue
    if (inProcessLockMap.get(key) === nextLockPromise) {
      inProcessLockMap.delete(key);
    }
  }
}
