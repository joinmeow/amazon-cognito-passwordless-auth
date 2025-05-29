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
const STALE_LOCK_TIMEOUT_MS = 30000; // Consider locks older than 30s as stale

// In-process FIFO lock queue
const inProcessLockMap = new Map<string, Promise<void>>();

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
  if (typeof globalThis.crypto !== 'undefined' && globalThis.crypto.randomUUID) {
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
      typeof data === 'object' &&
      'id' in data &&
      typeof data.id === 'string' &&
      'timestamp' in data &&
      typeof data.timestamp === 'number'
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
 * Check if a lock is stale
 */
function isLockStale(lockData: LockData): boolean {
  return Date.now() - lockData.timestamp > STALE_LOCK_TIMEOUT_MS;
}

/**
 * Acquire a simple storage-based lock on `key`, run `fn`, then release the lock.
 * Retries until timeoutMs if lock is already held.
 * Uses an in-process lock to ensure proper ordering within the same tab.
 */
export async function withStorageLock<T>(
  key: string,
  fn: () => Promise<T>,
  timeoutMs = DEFAULT_TIMEOUT_MS
): Promise<T> {
  const { storage, debug } = configure();
  debug?.("withStorageLock: attempting to acquire lock", key, { timeoutMs });

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

  try {
    await Promise.race([previous, timeoutPromise]);
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
    typeof globalThis !== "undefined" && typeof globalThis.addEventListener === "function";
  let onStorage: (e: StorageEvent) => void = () => {};

  // Generate unique lock ID for this attempt
  const lockId = generateLockId();
  const lockData: LockData = {
    id: lockId,
    timestamp: Date.now(),
  };

  if (isBrowser) {
    onStorage = (e: StorageEvent) => {
      if (e.key === key && (!e.newValue || e.newValue !== JSON.stringify(lockData))) {
        lockReleased = true;
      }
    };
    globalThis.addEventListener("storage", onStorage);
  }

  try {
    // Spin until storage lock is free, timeout, or notified by storage event
    while (!lockReleased) {
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
        debug?.("withStorageLock: timeout acquiring lock", key, { elapsed: Date.now() - start });
        throw new Error(`Timeout acquiring lock: ${key}`);
      }
      
      await sleep(DEFAULT_RETRY_DELAY_MS);
    }
  } finally {
    if (isBrowser) {
      globalThis.removeEventListener("storage", onStorage);
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
        debug?.("withStorageLock: acquired lock", key, { lockId, attempt });
        break;
      } else {
        debug?.("withStorageLock: lock acquisition race detected", key, { 
          ourId: lockId, 
          actualId: verifyLock?.id,
          attempt 
        });
        
        // Small backoff before retry
        if (attempt < maxAcquisitionAttempts) {
          await sleep(DEFAULT_RETRY_DELAY_MS * attempt);
        }
      }
    } catch (err) {
      debug?.("withStorageLock: storage error during lock acquisition", key, err);
      // Handle storage errors (quota exceeded, disabled storage, etc.)
      if (attempt === maxAcquisitionAttempts) {
        throw new Error(`Failed to acquire lock due to storage error: ${String(err)}`);
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
