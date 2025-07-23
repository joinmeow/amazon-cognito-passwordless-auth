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

// Mock localStorage for jsdom
import "jest-localstorage-mock";

// Mock setTimeoutWallClock from util.js
jest.mock("../util.js", () => {
  // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
  const actualUtil = jest.requireActual("../util.js");
  return {
    ...(actualUtil as object),
    setTimeoutWallClock: (fn: () => void, delay: number) => {
      const timeoutId = setTimeout(fn, delay);
      // Return a cleanup function like the real implementation
      return () => clearTimeout(timeoutId);
    },
    parseJwtPayload: (token: string) => {
      // Simple mock implementation that handles any JWT format
      try {
        // If it's our specific test token, return predefined values
        // Using length check first to avoid timing attacks
        if (token.length === 17 && token === "mock-access-token") {
          return {
            username: "test-user",
            exp: Math.floor(Date.now() / 1000) + 3600,
          };
        }

        // Otherwise, try to parse it as a real JWT
        const [, payload] = token.split(".");
        if (!payload) {
          throw new Error("Invalid token format");
        }

        // Decode base64url
        const base64 = payload.replace(/-/g, "+").replace(/_/g, "/");
        const decoded = atob(base64);
        return JSON.parse(decoded) as Record<string, unknown>;
      } catch (error) {
        throw new Error("Invalid token");
      }
    },
  };
});

// Mock window.crypto for WebAuthn tests
Object.defineProperty(globalThis, "crypto", {
  value: {
    getRandomValues: (arr: Uint8Array) => {
      for (let i = 0; i < arr.length; i++) {
        // eslint-disable-next-line security/detect-object-injection
        arr[i] = Math.floor(Math.random() * 256);
      }
      return arr;
    },
  },
});

// Mock fetch globally
global.fetch = jest.fn();

// Mock window.location - don't do it here as it causes issues
// Individual tests can mock location as needed

// Reset mocks between tests
beforeEach(() => {
  jest.clearAllMocks();
  localStorage.clear();
});
