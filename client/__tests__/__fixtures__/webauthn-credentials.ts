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
 * WebAuthn Test Fixtures - Known credential data for deterministic testing
 *
 * These fixtures represent real WebAuthn credential structures with known values
 * to enable precise validation instead of just checking for presence.
 */

/**
 * Base64URL encoding/decoding utilities for test fixtures
 */
export function base64UrlEncode(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  let binary = "";
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
}

export function base64UrlDecode(str: string): ArrayBuffer {
  const base64 = str.replace(/-/g, "+").replace(/_/g, "/");
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}

/**
 * Known test user data
 */
export const TEST_USER = {
  id: new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]),
  name: "test@example.com",
  displayName: "Test User",
} as const;

/**
 * Known test credential ID (deterministic)
 */
export const TEST_CREDENTIAL_ID = new Uint8Array([
  0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
  0x0e, 0x0f, 0x10,
]);

export const TEST_CREDENTIAL_ID_B64 = base64UrlEncode(
  TEST_CREDENTIAL_ID.buffer
);

/**
 * Known authenticator data (37 bytes minimum for assertion)
 * Format: RP ID hash (32) + flags (1) + counter (4)
 */
export const TEST_AUTHENTICATOR_DATA = new Uint8Array([
  // RP ID hash (SHA-256 of "example.com")
  0x49, 0x96, 0x0d, 0xe5, 0x88, 0x0e, 0x8c, 0x68, 0x74, 0x34, 0x17, 0x0f, 0x64,
  0x76, 0x60, 0x5b, 0x8f, 0xe4, 0xae, 0xb9, 0xa2, 0x86, 0x32, 0xc7, 0x99, 0x5c,
  0xf3, 0xba, 0x83, 0x1d, 0x97, 0x63,
  // Flags: UP (user present) + UV (user verified)
  0x05,
  // Counter (4 bytes, big-endian): 42
  0x00, 0x00, 0x00, 0x2a,
]);

/**
 * Known client data JSON
 */
export const TEST_CLIENT_DATA = {
  type: "webauthn.get",
  challenge: "dGVzdC1jaGFsbGVuZ2U", // base64url("test-challenge")
  origin: "https://example.com",
  crossOrigin: false,
} as const;

// Use manual encoding for Jest compatibility (TextEncoder not available in all test environments)
const clientDataString = JSON.stringify(TEST_CLIENT_DATA);
export const TEST_CLIENT_DATA_JSON = new Uint8Array(
  clientDataString.split("").map((c) => c.charCodeAt(0))
);

/**
 * Known signature (64 bytes for ES256)
 */
export const TEST_SIGNATURE = new Uint8Array([
  0x30, 0x45, 0x02, 0x21, 0x00, 0xf3, 0xac, 0x1c, 0x7f, 0x3e, 0xa8, 0x19, 0x5d,
  0x7e, 0x4e, 0x4a, 0x6f, 0x3f, 0x8c, 0x7a, 0x5e, 0x8d, 0x3f, 0x9e, 0x1c, 0x2a,
  0x5f, 0x7e, 0x9c, 0x3d, 0x8f, 0x4e, 0x5a, 0x6c, 0x7d, 0x8e, 0x02, 0x20, 0x5f,
  0x7e, 0x9c, 0x3d, 0x8f, 0x4e, 0x5a, 0x6c, 0x7d, 0x8e, 0x3f, 0x9e, 0x1c, 0x2a,
  0x5f, 0x7e, 0x9c, 0x3d, 0x8f, 0x4e, 0x5a, 0x6c, 0x7d, 0x8e, 0x3f, 0x9e,
]);

/**
 * Known user handle (same as user.id)
 */
export const TEST_USER_HANDLE = TEST_USER.id;

/**
 * Complete mock credential response (assertion)
 */
export const MOCK_ASSERTION_CREDENTIAL: PublicKeyCredential = {
  id: TEST_CREDENTIAL_ID_B64,
  rawId: TEST_CREDENTIAL_ID.buffer,
  type: "public-key",
  response: {
    authenticatorData: TEST_AUTHENTICATOR_DATA.buffer,
    clientDataJSON: TEST_CLIENT_DATA_JSON.buffer,
    signature: TEST_SIGNATURE.buffer,
    userHandle: TEST_USER_HANDLE.buffer,
  } as AuthenticatorAssertionResponse,
  authenticatorAttachment: "platform",
  getClientExtensionResults: () => ({}),
} as PublicKeyCredential;

/**
 * Known attestation object for credential creation
 */
// CBOR header for attestation object
const attestationHeader = new Uint8Array([
  0xa3, 0x63, 0x66, 0x6d, 0x74, 0x66, 0x70, 0x61, 0x63, 0x6b, 0x65, 0x64, 0x67,
  0x61, 0x74, 0x74, 0x53, 0x74, 0x6d, 0x74, 0xa0, 0x68, 0x61, 0x75, 0x74, 0x68,
  0x44, 0x61, 0x74, 0x61, 0x58, 0x25,
]);

export const TEST_ATTESTATION_OBJECT = new Uint8Array([
  ...Array.from(attestationHeader),
  ...Array.from(TEST_AUTHENTICATOR_DATA),
]);

/**
 * Complete mock credential response (attestation)
 */
export const MOCK_ATTESTATION_CREDENTIAL: PublicKeyCredential = {
  id: TEST_CREDENTIAL_ID_B64,
  rawId: TEST_CREDENTIAL_ID.buffer,
  type: "public-key",
  response: {
    attestationObject: TEST_ATTESTATION_OBJECT.buffer,
    clientDataJSON: TEST_CLIENT_DATA_JSON.buffer,
    getAuthenticatorData: () => TEST_AUTHENTICATOR_DATA.buffer,
    getPublicKey: () => new Uint8Array(65).buffer, // P-256 public key (65 bytes)
    getPublicKeyAlgorithm: () => -7, // ES256
    getTransports: () => ["internal", "hybrid"],
  } as AuthenticatorAttestationResponse,
  authenticatorAttachment: "platform",
  getClientExtensionResults: () => ({}),
} as PublicKeyCredential;

/**
 * Known extension results
 */
export const TEST_EXTENSION_RESULTS = {
  appid: false,
  credProps: {
    rk: true,
  },
  largeBlob: {
    supported: true,
  },
} as const;

/**
 * Mock credential with extensions
 */
export const MOCK_CREDENTIAL_WITH_EXTENSIONS: PublicKeyCredential = {
  ...MOCK_ASSERTION_CREDENTIAL,
  getClientExtensionResults: () => TEST_EXTENSION_RESULTS,
} as PublicKeyCredential;

/**
 * Known challenges for testing
 */
export const TEST_CHALLENGES = {
  basic: "dGVzdC1jaGFsbGVuZ2U", // "test-challenge"
  long: "VGhpcyBpcyBhIGxvbmdlciB0ZXN0IGNoYWxsZW5nZSBmb3IgdGVzdGluZyBiYXNlNjR1cmwgZW5jb2Rpbmc",
  special: "ISQlXiYqKCkrLT1bXXt9fDtcOiciLC4vPD4_", // Special chars
} as const;

/**
 * Known relying party configurations
 */
export const TEST_RP = {
  id: "example.com",
  name: "Example Corp",
} as const;

/**
 * Known WebAuthn client capabilities
 */
export const TEST_CAPABILITIES = {
  conditionalGet: true,
  immediateGet: true,
  conditionalCreate: false,
  passkeyPlatformAuthenticator: true,
  userVerifyingPlatformAuthenticator: true,
  hybridTransport: true,
  relatedOrigins: false,
  signalAllAcceptedCredentials: true,
  signalCurrentUserDetails: true,
  signalUnknownCredential: false,
} as const;

/**
 * Expected transformed credential (after fido2getCredential processing)
 */
export const EXPECTED_TRANSFORMED_CREDENTIAL = {
  credentialIdB64: TEST_CREDENTIAL_ID_B64,
  authenticatorDataB64: base64UrlEncode(TEST_AUTHENTICATOR_DATA.buffer),
  clientDataJSON_B64: base64UrlEncode(TEST_CLIENT_DATA_JSON.buffer),
  signatureB64: base64UrlEncode(TEST_SIGNATURE.buffer),
  userHandleB64: base64UrlEncode(TEST_USER_HANDLE.buffer),
} as const;
