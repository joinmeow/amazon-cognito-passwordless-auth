import { Blob as NodeBlob } from "buffer";
import { webcrypto } from "crypto";
import { TextEncoder as NodeTextEncoder } from "util";
import { configure, MinimalCrypto } from "../client/config.js";

// jsdom does not provide TextEncoder
if (typeof globalThis.TextEncoder === "undefined") {
  globalThis.TextEncoder = NodeTextEncoder as typeof globalThis.TextEncoder;
}

// jsdom's Blob lacks arrayBuffer(); use Node's implementation
if (typeof Blob.prototype.arrayBuffer !== "function") {
  globalThis.Blob = NodeBlob as unknown as typeof Blob;
}
import {
  getConstants,
  modPow,
  padHex,
  hexToArrayBuffer,
  arrayBufferToHex,
  arrayBufferToBigInt,
  calculateSrpSignature,
} from "../client/srp.js";
import { bufferFromBase64, bufferToBase64 } from "../client/util.js";

const subtle = webcrypto.subtle;

const USER_POOL_ID = "us-west-2_testpool1";
const USERNAME = "testuser";
const PASSWORD = "correct horse battery staple";
const SALT_HEX = "aabbccddeeff112233";
const SECRET_BLOCK_B64 = "c2VjcmV0YmxvY2s="; // base64("secretblock")

// Fixed private ephemeral (normally random)
const SMALL_A = BigInt("0x" + "12ab34cd".repeat(16));

async function computeUBuf(largeAHex: string, srpBHex: string) {
  return subtle.digest(
    "SHA-256",
    hexToArrayBuffer(padHex(largeAHex) + padHex(srpBHex))
  );
}

/**
 * Find an SRP_B value (as g^b mod N) whose scramble parameter
 * u = SHA256(A || B) hashes to a digest matching the given predicate.
 */
async function findSrpBHex(
  largeAHex: string,
  predicate: (uBytes: Uint8Array) => boolean
) {
  const { g, N } = await getConstants();
  for (let b = BigInt(2); b < BigInt(10000); b += BigInt(1)) {
    const srpBHex = modPow(g, b, N).toString(16);
    const uBuf = await computeUBuf(largeAHex, srpBHex);
    if (predicate(new Uint8Array(uBuf))) {
      return srpBHex;
    }
  }
  throw new Error("no suitable SRP_B found");
}

/**
 * Reference implementation of the Cognito SRP password claim signature,
 * mirroring amazon-cognito-identity-js: the HKDF salt is the scramble
 * parameter u encoded as a BIG INTEGER (leading zero bytes stripped,
 * '00' sign byte prepended when the top bit is set). The salt encoding is
 * parameterized so the test can also compute what the buggy (raw digest
 * hex) encoding would have produced.
 */
async function referenceSignature({
  largeAHex,
  srpBHex,
  timestamp,
  saltHkdfHexOf,
}: {
  largeAHex: string;
  srpBHex: string;
  timestamp: string;
  saltHkdfHexOf: (uBuf: ArrayBuffer) => string;
}) {
  const { g, N, k } = await getConstants();
  const [, userPoolName] = USER_POOL_ID.split("_");

  const uBuf = await computeUBuf(largeAHex, srpBHex);
  const identityHash = await subtle.digest(
    "SHA-256",
    new TextEncoder().encode(`${userPoolName}${USERNAME}:${PASSWORD}`)
  );
  const saltBytes = hexToArrayBuffer(padHex(SALT_HEX));
  const xInput = new Uint8Array(saltBytes.length + identityHash.byteLength);
  xInput.set(saltBytes, 0);
  xInput.set(new Uint8Array(identityHash), saltBytes.length);
  const xBuf = await subtle.digest("SHA-256", xInput);

  const x = arrayBufferToBigInt(xBuf);
  const u = arrayBufferToBigInt(uBuf);
  const s = modPow(
    BigInt(`0x${srpBHex}`) - k * modPow(g, x, N),
    SMALL_A + u * x,
    N
  );

  // HKDF: extract with salt=u (big-integer encoded), expand with info bits
  const prkKey = await subtle.importKey(
    "raw",
    hexToArrayBuffer(saltHkdfHexOf(uBuf)),
    { name: "HMAC", hash: { name: "SHA-256" } },
    false,
    ["sign"]
  );
  const prk = await subtle.sign(
    "HMAC",
    prkKey,
    hexToArrayBuffer(padHex(s.toString(16)))
  );
  const hkdfKey = await subtle.importKey(
    "raw",
    prk,
    { name: "HMAC", hash: { name: "SHA-256" } },
    false,
    ["sign"]
  );
  const infoBits = new Uint8Array([
    ..."Caldera Derived Key".split("").map((c) => c.charCodeAt(0)),
    1,
  ]).buffer;
  const hkdf = (await subtle.sign("HMAC", hkdfKey, infoBits)).slice(0, 16);

  const msg = new Uint8Array(
    [
      userPoolName.split("").map((c) => c.charCodeAt(0)),
      USERNAME.split("").map((c) => c.charCodeAt(0)),
      ...bufferFromBase64(SECRET_BLOCK_B64),
      timestamp.split("").map((c) => c.charCodeAt(0)),
    ].flat()
  ).buffer;
  const signatureKey = await subtle.importKey(
    "raw",
    hkdf,
    { name: "HMAC", hash: { name: "SHA-256" } },
    false,
    ["sign"]
  );
  return bufferToBase64(await subtle.sign("HMAC", signatureKey, msg));
}

async function actualSignature(largeAHex: string, srpBHex: string) {
  return calculateSrpSignature({
    smallA: SMALL_A,
    largeAHex,
    srpBHex,
    salt: SALT_HEX,
    secretBlock: SECRET_BLOCK_B64,
    creds: {
      userPoolId: USER_POOL_ID,
      username: USERNAME,
      password: PASSWORD,
    },
  });
}

describe("SRP HKDF salt encoding", () => {
  let largeAHex: string;

  beforeAll(async () => {
    configure({
      clientId: "testClient",
      cognitoIdpEndpoint: "us-west-2",
      userPoolId: USER_POOL_ID,
      crypto: webcrypto as unknown as MinimalCrypto,
    });
    const { g, N } = await getConstants();
    largeAHex = modPow(g, SMALL_A, N).toString(16);
  });

  test("padHex mirrors Java BigInteger.toByteArray semantics", () => {
    expect(padHex("abc")).toBe("0abc"); // odd length gets zero-padded
    expect(padHex("7f")).toBe("7f"); // top bit clear: unchanged
    expect(padHex("ff")).toBe("00ff"); // top bit set: '00' sign byte
    expect(padHex("8a01")).toBe("008a01");
  });

  test("u with leading zero byte: salt must use big-integer encoding (leading zeros stripped)", async () => {
    // Craft an SRP_B whose u = SHA256(A || B) starts with a 0x00 byte
    // followed by a byte < 0x80. For such u, the raw digest hex and the
    // big-integer hex encodings diverge (~1 in 516 sign-ins).
    const srpBHex = await findSrpBHex(
      largeAHex,
      (u) => u[0] === 0x00 && u[1] < 0x80
    );
    const uBuf = await computeUBuf(largeAHex, srpBHex);
    const rawHex = arrayBufferToHex(uBuf);
    const bigIntHex = padHex(arrayBufferToBigInt(uBuf).toString(16));
    // Sanity check: the two encodings differ for this crafted u
    expect(bigIntHex).not.toBe(padHex(rawHex));

    const { passwordClaimSignature, timestamp } = await actualSignature(
      largeAHex,
      srpBHex
    );
    const expected = await referenceSignature({
      largeAHex,
      srpBHex,
      timestamp,
      saltHkdfHexOf: (u) => padHex(arrayBufferToBigInt(u).toString(16)),
    });
    const buggy = await referenceSignature({
      largeAHex,
      srpBHex,
      timestamp,
      saltHkdfHexOf: (u) => padHex(arrayBufferToHex(u)),
    });
    expect(passwordClaimSignature).toBe(expected);
    expect(passwordClaimSignature).not.toBe(buggy);
  });

  test("u with top bit set: salt gets the '00' sign byte", async () => {
    const srpBHex = await findSrpBHex(largeAHex, (u) => u[0] >= 0x80);
    const uBuf = await computeUBuf(largeAHex, srpBHex);
    const rawHex = arrayBufferToHex(uBuf);
    // Big-integer encoding prepends a '00' sign byte (Java
    // BigInteger.toByteArray semantics), matching the Cognito server.
    expect(padHex(arrayBufferToBigInt(uBuf).toString(16))).toBe(
      `00${rawHex}`
    );

    const { passwordClaimSignature, timestamp } = await actualSignature(
      largeAHex,
      srpBHex
    );
    const expected = await referenceSignature({
      largeAHex,
      srpBHex,
      timestamp,
      saltHkdfHexOf: (u) => padHex(arrayBufferToBigInt(u).toString(16)),
    });
    expect(passwordClaimSignature).toBe(expected);
  });
});
