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
 * Regression tests for device-verifier salt canonicalization.
 *
 * Cognito stores and echoes the device salt as a big integer: the SALT
 * ChallengeParameter returned in DEVICE_PASSWORD_VERIFIER challenges has any
 * leading zero bytes stripped. Before this fix, confirmation-time x was
 * hashed over the raw 16 random salt bytes (top bit cleared), so a salt with
 * a leading 0x00 byte (P ~ 1/128) produced a verifier that could never be
 * matched again at device sign-in time: the recomputed x - derived from the
 * echoed SALT hex via padHex - hashed over fewer bytes, permanently breaking
 * DEVICE_PASSWORD_VERIFIER auth for that device.
 *
 * The fix mirrors amazon-cognito-identity-js: the salt is canonicalized
 * through BigInt + padHex BEFORE hashing, and the same canonical bytes are
 * uploaded in DeviceSecretVerifierConfig.Salt, so what's hashed always equals
 * what the server stores and echoes back.
 */

// jsdom doesn't define TextDecoder/TextEncoder, nor Blob.arrayBuffer(), which
// the SRP calculations rely on. Provide Node's.
import { TextEncoder, TextDecoder } from "util";
import { Blob as NodeBlob } from "buffer";
import { webcrypto } from "crypto";
Object.assign(globalThis, {
  TextEncoder: globalThis.TextEncoder ?? TextEncoder,
  TextDecoder: globalThis.TextDecoder ?? TextDecoder,
  Blob: NodeBlob,
});

import { configure, MinimalCrypto } from "../config.js";
import { calculateDeviceVerifier } from "../device.js";
import {
  getConstants,
  modPow,
  padHex,
  hexToArrayBuffer,
  arrayBufferToHex,
  arrayBufferToBigInt,
} from "../srp.js";
import { bufferFromBase64, bufferToBase64 } from "../util.js";

const DEVICE_KEY = "eu-west-1_12345678-1234-1234-1234-123456789012";
const DEVICE_GROUP_KEY = "-fakeGroupKey";
const DEVICE_PASSWORD = "secret-device-password";

/** The next salt that the mocked crypto.getRandomValues will produce */
let nextSalt: Uint8Array | undefined;

const testCrypto: MinimalCrypto = {
  getRandomValues: <T extends ArrayBufferView | null>(arr: T): T => {
    if (!(arr instanceof Uint8Array)) {
      throw new Error("Unexpected getRandomValues argument in test");
    }
    if (nextSalt) {
      if (nextSalt.length !== arr.length) {
        throw new Error("Crafted salt length mismatch");
      }
      arr.set(nextSalt);
      nextSalt = undefined;
    } else {
      webcrypto.getRandomValues(arr);
    }
    return arr;
  },
  subtle: {
    digest: webcrypto.subtle.digest.bind(webcrypto.subtle),
    importKey: webcrypto.subtle.importKey.bind(
      webcrypto.subtle
    ) as MinimalCrypto["subtle"]["importKey"],
    sign: webcrypto.subtle.sign.bind(webcrypto.subtle),
  },
};

beforeAll(() => {
  configure({
    userPoolId: "eu-west-1_test",
    clientId: "test-client-id",
    crypto: testCrypto,
  });
});

/**
 * Recompute the device password verifier the way later device sign-ins do
 * (srp.ts calculateSrpSignature): x is hashed over
 * hexToArrayBuffer(padHex(SALT)) where SALT is the hex string echoed by
 * Cognito in the DEVICE_PASSWORD_VERIFIER ChallengeParameters.
 */
async function recomputeVerifierFromEchoedSalt(echoedSaltHex: string) {
  const fullPasswordHash = await testCrypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(
      `${DEVICE_GROUP_KEY}${DEVICE_KEY}:${DEVICE_PASSWORD}`
    )
  );
  const xBuf = await testCrypto.subtle.digest(
    "SHA-256",
    await new Blob([
      hexToArrayBuffer(padHex(echoedSaltHex)),
      fullPasswordHash,
    ]).arrayBuffer()
  );
  const { g, N } = await getConstants();
  const verifier = modPow(g, arrayBufferToBigInt(xBuf), N);
  return bufferToBase64(hexToArrayBuffer(padHex(verifier.toString(16))));
}

/**
 * Simulate Cognito's serialization of the stored salt: it's treated as a big
 * integer, so leading zero bytes are stripped from the echoed hex.
 */
function echoSaltAsBigIntegerHex(uploadedSaltB64: string) {
  const storedBytes = new Uint8Array(bufferFromBase64(uploadedSaltB64));
  return BigInt(`0x${arrayBufferToHex(storedBytes.buffer)}`).toString(16);
}

async function confirmAndSignIn(craftedSalt: Uint8Array) {
  nextSalt = craftedSalt;
  const { passwordVerifier, salt } = await calculateDeviceVerifier(
    "test-user",
    DEVICE_KEY,
    DEVICE_GROUP_KEY,
    DEVICE_PASSWORD
  );
  const echoedSaltHex = echoSaltAsBigIntegerHex(salt);
  const recomputedVerifier = await recomputeVerifierFromEchoedSalt(
    echoedSaltHex
  );
  return { passwordVerifier, salt, recomputedVerifier };
}

describe("device verifier salt canonicalization", () => {
  test("salt with leading zero byte: uploaded salt is the canonical big-integer encoding and sign-in x matches confirmation x", async () => {
    // First byte 0x00 and second byte < 0x80: a big-integer round-trip strips
    // the leading zero byte for good (padHex won't re-add it). This is the
    // case that permanently broke DEVICE_PASSWORD_VERIFIER before the fix.
    const craftedSalt = new Uint8Array([
      0x00, 0x5a, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa,
      0xbb, 0xcc, 0xdd, 0xee,
    ]);
    const { passwordVerifier, salt, recomputedVerifier } =
      await confirmAndSignIn(craftedSalt);

    // The uploaded salt must be the canonical big-integer encoding (leading
    // zero byte stripped), i.e. exactly what Cognito will store and echo back
    const canonicalHex = padHex(
      arrayBufferToBigInt(craftedSalt.buffer).toString(16)
    );
    expect(arrayBufferToHex(bufferFromBase64(salt))).toBe(canonicalHex);
    expect(bufferFromBase64(salt).byteLength).toBe(15);

    // Sign-in-time x (recomputed from the echoed SALT) must agree with
    // confirmation-time x, i.e. yield the registered verifier
    expect(recomputedVerifier).toBe(passwordVerifier);
  });

  test("salt with most significant bit set gets proper sign handling (00 prefix) and round-trips", async () => {
    const craftedSalt = new Uint8Array([
      0xff, 0x5a, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa,
      0xbb, 0xcc, 0xdd, 0xee,
    ]);
    const { passwordVerifier, salt, recomputedVerifier } =
      await confirmAndSignIn(craftedSalt);

    // padHex must prefix "00" to keep the big integer positive, like the
    // reference implementation (amazon-cognito-identity-js) does
    const saltBytes = new Uint8Array(bufferFromBase64(salt));
    expect(saltBytes.byteLength).toBe(17);
    expect(saltBytes[0]).toBe(0x00);
    expect(arrayBufferToHex(saltBytes.buffer)).toBe(
      `00${arrayBufferToHex(craftedSalt.buffer)}`
    );

    expect(recomputedVerifier).toBe(passwordVerifier);
  });

  test("ordinary salt (no leading zero, MSB clear) is uploaded as-is and round-trips", async () => {
    const craftedSalt = new Uint8Array([
      0x12, 0x5a, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa,
      0xbb, 0xcc, 0xdd, 0xee,
    ]);
    const { passwordVerifier, salt, recomputedVerifier } =
      await confirmAndSignIn(craftedSalt);

    expect(arrayBufferToHex(bufferFromBase64(salt))).toBe(
      arrayBufferToHex(craftedSalt.buffer)
    );
    expect(recomputedVerifier).toBe(passwordVerifier);
  });
});
