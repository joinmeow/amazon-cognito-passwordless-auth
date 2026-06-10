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
import { webcrypto } from "crypto";
import { TextEncoder } from "util";
import { configure, MinimalCrypto } from "../config.js";

// jsdom does not provide TextEncoder
if (typeof globalThis.TextEncoder === "undefined") {
  globalThis.TextEncoder = TextEncoder as typeof globalThis.TextEncoder;
}

// jsdom's Blob does not implement arrayBuffer(), node's Blob does
if (typeof Blob.prototype.arrayBuffer === "undefined") {
  // eslint-disable-next-line @typescript-eslint/no-var-requires
  globalThis.Blob = require("buffer").Blob as typeof globalThis.Blob;
}
import {
  calculateSrpSignature,
  generateSmallA,
  calculateLargeAHex,
  getConstants,
  hexToArrayBuffer,
  modPow,
} from "../srp.js";

const realCrypto = webcrypto as unknown as MinimalCrypto;

function configureWithCrypto(crypto: MinimalCrypto) {
  configure({
    userPoolId: "eu-west-1_abc",
    clientId: "test-client",
    crypto,
  });
}

describe("SRP safety checks", () => {
  beforeEach(() => {
    configureWithCrypto(realCrypto);
  });

  describe("B mod N validation (RFC 5054 section 2.5.3)", () => {
    test("rejects B = 0", async () => {
      await expect(
        calculateSrpSignature({
          smallA: BigInt(1234),
          largeAHex: "abc",
          srpBHex: "0",
          salt: "ab12",
          secretBlock: "c2VjcmV0",
          creds: {
            userPoolId: "eu-west-1_abc",
            username: "alice",
            password: "secret",
          },
        })
      ).rejects.toThrow("B cannot be zero");
    });

    test("rejects B = N", async () => {
      const { N } = await getConstants();
      await expect(
        calculateSrpSignature({
          smallA: BigInt(1234),
          largeAHex: "abc",
          srpBHex: N.toString(16),
          salt: "ab12",
          secretBlock: "c2VjcmV0",
          creds: {
            userPoolId: "eu-west-1_abc",
            username: "alice",
            password: "secret",
          },
        })
      ).rejects.toThrow("B cannot be zero");
    });

    test("rejects B = 2N (any multiple of N)", async () => {
      const { N } = await getConstants();
      await expect(
        calculateSrpSignature({
          smallA: BigInt(1234),
          largeAHex: "abc",
          srpBHex: (N * BigInt(2)).toString(16),
          salt: "ab12",
          secretBlock: "c2VjcmV0",
          creds: {
            deviceGroupKey: "group-key",
            deviceKey: "device-key",
            devicePassword: "device-secret",
          },
        })
      ).rejects.toThrow("B cannot be zero");
    });
  });

  describe("u != 0 validation (SRP-6a design)", () => {
    test("rejects u = 0", async () => {
      // Make sure the SRP constants are cached before mocking the digest,
      // so that the mock only affects the computation of u
      await getConstants();
      const zeroDigestCrypto: MinimalCrypto = {
        getRandomValues: realCrypto.getRandomValues.bind(realCrypto),
        subtle: {
          digest: () => Promise.resolve(new Uint8Array(32).buffer),
          importKey: realCrypto.subtle.importKey.bind(realCrypto.subtle),
          sign: realCrypto.subtle.sign.bind(realCrypto.subtle),
        },
      };
      configureWithCrypto(zeroDigestCrypto);
      await expect(
        calculateSrpSignature({
          smallA: BigInt(1234),
          largeAHex: "abc",
          srpBHex: "5",
          salt: "ab12",
          secretBlock: "c2VjcmV0",
          creds: {
            userPoolId: "eu-west-1_abc",
            username: "alice",
            password: "secret",
          },
        })
      ).rejects.toThrow("U cannot be zero");
    });
  });

  test("accepts a well-formed B and produces a signature", async () => {
    const { g, N } = await getConstants();
    const smallA = generateSmallA();
    const largeAHex = await calculateLargeAHex(smallA);
    // Craft a structurally valid (non-degenerate) server B value
    const srpBHex = modPow(g, BigInt(98765), N).toString(16);
    const { passwordClaimSignature, timestamp } = await calculateSrpSignature({
      smallA,
      largeAHex,
      srpBHex,
      salt: "ab12",
      secretBlock: "c2VjcmV0",
      creds: {
        userPoolId: "eu-west-1_abc",
        username: "alice",
        password: "secret",
      },
    });
    expect(typeof passwordClaimSignature).toBe("string");
    expect(passwordClaimSignature.length).toBeGreaterThan(0);
    expect(typeof timestamp).toBe("string");
  });

  describe("hexToArrayBuffer input validation", () => {
    test("throws a clear error on empty input", () => {
      expect(() => hexToArrayBuffer("")).toThrow(
        "hex string should be non-empty and contain only hex characters"
      );
    });

    test("throws a clear error on non-hex input", () => {
      expect(() => hexToArrayBuffer("zzzz")).toThrow(
        "hex string should be non-empty and contain only hex characters"
      );
    });

    test("throws on odd-length input", () => {
      expect(() => hexToArrayBuffer("abc")).toThrow(
        "hex string should have even number of characters"
      );
    });

    test("decodes valid hex", () => {
      expect([...hexToArrayBuffer("00ff10")]).toEqual([0, 255, 16]);
    });
  });
});
