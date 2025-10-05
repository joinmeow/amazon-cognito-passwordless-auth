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

/**
 * WebAuthn Mock Factory Utilities - Gold Standard Test Setup
 *
 * Centralized, reusable mock factories for WebAuthn testing.
 * Provides consistent, deterministic mocking with proper cleanup.
 */

import {
  MOCK_ASSERTION_CREDENTIAL,
  MOCK_ATTESTATION_CREDENTIAL,
  TEST_CAPABILITIES,
  TEST_CREDENTIAL_ID,
  TEST_USER,
  base64UrlEncode,
} from "../__fixtures__/webauthn-credentials.js";

/**
 * WebAuthn mock configuration options
 */
export interface WebAuthnMockConfig {
  /** Whether PublicKeyCredential API is available */
  available?: boolean;
  /** Whether conditional UI is supported */
  conditionalMediationSupported?: boolean;
  /** Mock credential to return from get() */
  credential?: PublicKeyCredential | null;
  /** Mock credential to return from create() */
  createCredential?: PublicKeyCredential | null;
  /** Error to throw from get() */
  getError?: Error | DOMException | null;
  /** Error to throw from create() */
  createError?: Error | DOMException | null;
  /** Client capabilities to return */
  capabilities?: Record<string, boolean | undefined>;
  /** Custom navigator.credentials implementation */
  customCredentials?: CredentialsContainer;
}

/**
 * Create a mock PublicKeyCredential with custom properties
 */
export function createMockCredential(
  overrides: Partial<PublicKeyCredential> = {}
): PublicKeyCredential {
  return {
    ...MOCK_ASSERTION_CREDENTIAL,
    ...overrides,
  } as PublicKeyCredential;
}

/**
 * Create a mock attestation credential for creation flows
 */
export function createMockAttestationCredential(
  overrides: Partial<PublicKeyCredential> = {}
): PublicKeyCredential {
  return {
    ...MOCK_ATTESTATION_CREDENTIAL,
    ...overrides,
  } as PublicKeyCredential;
}

/**
 * Create a mock DOMException for WebAuthn errors
 */
export function createWebAuthnError(
  name: string,
  message: string
): DOMException {
  // Use native DOMException if available (Node 18+, jsdom)
  if (typeof DOMException !== "undefined") {
    return new DOMException(message, name);
  }

  // Fallback for older environments
  const error = new Error(message) as Error & { name: string; code?: number };
  error.name = name;

  // Add DOMException-specific properties
  Object.defineProperty(error, "code", {
    value: getDOMExceptionCode(name),
    enumerable: true,
  });

  return error as unknown as DOMException;
}

/**
 * Get standard DOMException code for error name
 */
function getDOMExceptionCode(name: string): number {
  const codes: Record<string, number> = {
    NotAllowedError: 35,
    AbortError: 20,
    SecurityError: 18,
    InvalidStateError: 11,
    NotSupportedError: 9,
  };
  return codes[name] || 0;
}

/**
 * Setup WebAuthn global mocks with full configuration
 *
 * This is the main entry point for test setup. Provides:
 * - Proper PublicKeyCredential mock
 * - navigator.credentials mock
 * - Conditional UI support detection
 * - Client capabilities API
 * - Automatic cleanup on teardown
 */
export function setupWebAuthnMock(config: WebAuthnMockConfig = {}): () => void {
  const {
    available = true,
    conditionalMediationSupported = true,
    credential = MOCK_ASSERTION_CREDENTIAL,
    createCredential = MOCK_ATTESTATION_CREDENTIAL,
    getError = null,
    createError = null,
    capabilities = TEST_CAPABILITIES,
    customCredentials = null,
  } = config;

  // Store original values for cleanup
  // eslint-disable-next-line @typescript-eslint/no-explicit-any, @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-member-access
  const originalPublicKeyCredential = (global as any).PublicKeyCredential;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any, @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-member-access
  const originalNavigator = (global as any).navigator;

  if (!available) {
    // Simulate browser without WebAuthn support
    // eslint-disable-next-line @typescript-eslint/no-explicit-any, @typescript-eslint/no-unsafe-member-access
    delete (global as any).PublicKeyCredential;
    // eslint-disable-next-line @typescript-eslint/no-explicit-any, @typescript-eslint/no-unsafe-member-access
    delete (global as any).navigator;

    return () => {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any, @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-member-access
      (global as any).PublicKeyCredential = originalPublicKeyCredential;
      // eslint-disable-next-line @typescript-eslint/no-explicit-any, @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-member-access
      (global as any).navigator = originalNavigator;
    };
  }

  // Mock PublicKeyCredential with all required methods
  const mockPublicKeyCredential = {
    isUserVerifyingPlatformAuthenticatorAvailable: jest
      .fn()
      .mockResolvedValue(true),

    isConditionalMediationAvailable: conditionalMediationSupported
      ? jest.fn().mockResolvedValue(true)
      : undefined,

    getClientCapabilities: jest.fn().mockResolvedValue(capabilities),
  };

  // eslint-disable-next-line @typescript-eslint/no-explicit-any, @typescript-eslint/no-unsafe-member-access
  (global as any).PublicKeyCredential = mockPublicKeyCredential;

  // Mock navigator.credentials
  const mockCredentials = customCredentials || {
    get: jest.fn().mockImplementation(async (options) => {
      if (getError) throw getError;

      // Simulate abort signal
      if (options?.signal?.aborted) {
        throw createWebAuthnError("AbortError", "The operation was aborted");
      }

      return credential;
    }),

    create: jest.fn().mockImplementation(async () => {
      if (createError) throw createError;
      return createCredential;
    }),
  };

  // In jsdom, navigator is provided as a getter and credentials doesn't exist by default
  // We need to define credentials property on the existing navigator object
  // eslint-disable-next-line @typescript-eslint/no-explicit-any, @typescript-eslint/no-unsafe-member-access
  if ((global as any).navigator) {
    // Navigator exists (jsdom), define credentials on it
    // eslint-disable-next-line @typescript-eslint/no-explicit-any, @typescript-eslint/no-unsafe-member-access
    Object.defineProperty((global as any).navigator, "credentials", {
      value: mockCredentials,
      configurable: true,
      writable: true,
    });
  } else {
    // Navigator doesn't exist, create it with credentials
    // eslint-disable-next-line @typescript-eslint/no-explicit-any, @typescript-eslint/no-unsafe-member-access
    (global as any).navigator = {
      credentials: mockCredentials,
    };
  }

  // Return cleanup function
  return () => {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any, @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-member-access
    (global as any).PublicKeyCredential = originalPublicKeyCredential;
    // eslint-disable-next-line @typescript-eslint/no-explicit-any, @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-member-access
    (global as any).navigator = originalNavigator;
  };
}

/**
 * Setup minimal WebAuthn mock for simple tests
 */
export function setupMinimalWebAuthnMock(): () => void {
  return setupWebAuthnMock({
    available: true,
    conditionalMediationSupported: true,
  });
}

/**
 * Setup WebAuthn mock that simulates user cancellation
 */
export function setupCancelledWebAuthnMock(): () => void {
  return setupWebAuthnMock({
    getError: createWebAuthnError(
      "NotAllowedError",
      "The operation was cancelled by the user"
    ),
  });
}

/**
 * Setup WebAuthn mock that simulates timeout/abort
 */
export function setupAbortedWebAuthnMock(): () => void {
  return setupWebAuthnMock({
    getError: createWebAuthnError("AbortError", "The operation was aborted"),
  });
}

/**
 * Setup WebAuthn mock without conditional mediation support
 */
export function setupNoConditionalMediationMock(): () => void {
  return setupWebAuthnMock({
    conditionalMediationSupported: false,
    capabilities: {
      ...TEST_CAPABILITIES,
      conditionalGet: false,
    },
  });
}

/**
 * Setup WebAuthn mock without browser support
 */
export function setupNoBrowserSupportMock(): () => void {
  return setupWebAuthnMock({
    available: false,
  });
}

/**
 * Create a mock fetch response for Cognito API
 */
export function createMockCognitoResponse(data: any, status = 200): Response {
  return {
    ok: status >= 200 && status < 300,
    status,
    statusText: status === 200 ? "OK" : "Error",
    json: async () => data,
    text: async () => JSON.stringify(data),
  } as Response;
}

/**
 * Create mock Cognito challenge response
 */
export function createMockChallengeResponse(challenge = "dGVzdC1jaGFsbGVuZ2U") {
  return {
    challenge,
    userId: base64UrlEncode(TEST_USER.id.buffer),
    username: TEST_USER.name,
    allowCredentials: [
      {
        id: base64UrlEncode(TEST_CREDENTIAL_ID.buffer),
        type: "public-key",
        transports: ["internal", "hybrid"],
      },
    ],
  };
}

/**
 * Create a mock abort controller with signal
 */
export function createMockAbortController(): {
  controller: AbortController;
  abort: () => void;
} {
  const controller = new AbortController();
  return {
    controller,
    abort: () => controller.abort(),
  };
}

/**
 * Assert that a credential matches expected fixture values
 */
export function assertCredentialMatches(
  actual: any,
  expected: PublicKeyCredential
): void {
  expect(actual.id).toBe(expected.id);
  expect(actual.type).toBe(expected.type);
  expect(actual.rawId).toEqual(expected.rawId);

  if ("authenticatorData" in expected.response) {
    const actualResponse = actual.response as AuthenticatorAssertionResponse;
    const expectedResponse =
      expected.response as AuthenticatorAssertionResponse;
    expect(actualResponse.authenticatorData).toEqual(
      expectedResponse.authenticatorData
    );
    expect(actualResponse.clientDataJSON).toEqual(
      expectedResponse.clientDataJSON
    );
    expect(actualResponse.signature).toEqual(expectedResponse.signature);
    expect(actualResponse.userHandle).toEqual(expectedResponse.userHandle);
  }
}

/**
 * Assert that transformed credential matches expected base64 values
 */
export function assertTransformedCredentialMatches(
  actual: any,
  expected: {
    credentialIdB64: string;
    authenticatorDataB64: string;
    clientDataJSON_B64: string;
    signatureB64: string;
    userHandleB64: string;
  }
): void {
  expect(actual.credentialIdB64).toBe(expected.credentialIdB64);
  expect(actual.authenticatorDataB64).toBe(expected.authenticatorDataB64);
  expect(actual.clientDataJSON_B64).toBe(expected.clientDataJSON_B64);
  expect(actual.signatureB64).toBe(expected.signatureB64);
  expect(actual.userHandleB64).toBe(expected.userHandleB64);
}

/**
 * Wait for async operations with timeout
 */
export async function waitFor(
  condition: () => boolean,
  timeout = 1000,
  interval = 50
): Promise<void> {
  const startTime = Date.now();
  while (!condition()) {
    if (Date.now() - startTime > timeout) {
      throw new Error("Timeout waiting for condition");
    }
    await new Promise((resolve) => setTimeout(resolve, interval));
  }
}
