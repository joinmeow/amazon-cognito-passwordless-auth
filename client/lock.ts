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
const STALE_LOCK_TIMEOUT_MS = 30000; // 30 seconds

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
      if (
        e.key === key &&
        (!e.newValue || e.newValue !== JSON.stringify(lockData))
      ) {
        debug?.("withStorageLock: storage event detected lock release", key);
        lockReleased = true;
      }
    };
    globalThis.addEventListener("storage", onStorage);
  }

  try {
    // Poll until lock is free or timeout
    let pollDelay = DEFAULT_RETRY_DELAY_MS;
    const maxPollDelay = 500;
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
      if (Date.now() - start > timeoutMs) {
        debug?.("withStorageLock: timeout acquiring lock", key, {
          elapsed: Date.now() - start,
        });
        throw new LockTimeoutError(key, timeoutMs);
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
    }
  }

  // Acquire lock with atomic check
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
        });

        // Small backoff before retry
        if (attempt < maxAcquisitionAttempts) {
          await sleep(DEFAULT_RETRY_DELAY_MS * attempt);
        }
      }
    } catch (error) {
      debug?.(
        "withStorageLock: storage error during lock acquisition",
        key,
        error
      );
      // Handle storage errors
      if (attempt === maxAcquisitionAttempts) {
        throw new Error(
          `Failed to acquire lock due to storage error: ${String(error)}`
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
    } catch (error) {
      // Log but don't throw - the operation succeeded
      debug?.("withStorageLock: error releasing lock", key, error);
    }
  }
}
