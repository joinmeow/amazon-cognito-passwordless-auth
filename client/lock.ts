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

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * Acquire a simple storage-based lock on `key`, run `fn`, then release the lock.
 * Retries until timeoutMs if lock is already held.
 */
export async function withStorageLock<T>(
  key: string,
  fn: () => Promise<T>,
  timeoutMs = 5000
): Promise<T> {
  const { storage } = configure();
  const start = Date.now();
  // Spin until lock is free or timeout
  while ((await storage.getItem(key)) === "true") {
    if (Date.now() - start > timeoutMs) {
      throw new Error(`Timeout acquiring lock: ${key}`);
    }
    await sleep(DEFAULT_RETRY_DELAY_MS);
  }
  // Acquire
  await storage.setItem(key, "true");
  try {
    return await fn();
  } finally {
    try {
      await storage.removeItem(key);
    } catch {
      // ignore remove errors
    }
  }
}
