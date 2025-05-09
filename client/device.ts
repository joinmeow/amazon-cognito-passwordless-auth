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

import { bufferToBase64, bufferFromBase64, bufferFromBase64Url } from "./util.js";
import {
  modPow,
  getConstants,
  hexToArrayBuffer,
  arrayBufferToHex,
  arrayBufferToBigInt,
  padHex,
} from "./srp.js";
import { TokensFromSignIn } from "./model.js";
import {
  storeDeviceKey,
  storeDeviceRememberedStatus,
  storeDevicePassword,
  retrieveDevicePassword,
} from "./storage.js";
import { confirmDevice } from "./cognito-api.js";

// Helper function to get device info for naming
function getDeviceName(): string {
  if (typeof navigator === "undefined") {
    return "Unknown Device";
  }

  const ua = navigator.userAgent;

  // Get OS type
  let os = "Unknown";
  if (ua.includes("iPhone")) os = "iPhone";
  else if (ua.includes("iPad")) os = "iPad";
  else if (ua.includes("Android")) os = "Android";
  else if (ua.includes("Windows")) os = "Windows";
  else if (ua.includes("Mac")) os = "Mac";
  else if (ua.includes("Linux")) os = "Linux";

  // Get browser type
  let browser = "";
  if (ua.includes("Chrome") && !ua.includes("Edg")) browser = "Chrome";
  else if (ua.includes("Firefox")) browser = "Firefox";
  else if (ua.includes("Safari") && !ua.includes("Chrome")) browser = "Safari";
  else if (ua.includes("Edg")) browser = "Edge";

  return browser ? `${os} ${browser}` : os;
}

/**
 * Generate a secure random device password for SRP calculations
 * @returns Base64-encoded random password
 */
async function generateDevicePassword(): Promise<string> {
  const { crypto } = configure();
  // Generate a random 40-byte password as used in the Python example
  const randomPasswordBuffer = new Uint8Array(40);
  crypto.getRandomValues(randomPasswordBuffer);
  return bufferToBase64(randomPasswordBuffer);
}

/**
 * Calculate SRP verification values for device confirmation
 * This follows the same pattern as the Python example
 */
async function calculateDeviceVerifier(
  username: string,
  deviceKey: string,
  deviceGroupKey: string,
  devicePassword: string
): Promise<{
  passwordVerifier: string;
  salt: string;
}> {
  const { crypto } = configure();

  // Generate salt
  const saltBuffer = new Uint8Array(16);
  crypto.getRandomValues(saltBuffer);
  // Ensure first bit is not set (making it positive)
  saltBuffer[0] = saltBuffer[0] & 0x7f;
  const salt = bufferToBase64(saltBuffer);

  // Create FULL_PASSWORD = SHA256_HASH(DeviceGroupKey + deviceKey + ":" + DEVICE_PASSWORD)
  const fullPasswordString = `${deviceGroupKey}${deviceKey}:${devicePassword}`;
  const fullPasswordHash = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(fullPasswordString)
  );

  // Create x = SHA256_HASH(salt + FULL_PASSWORD)
  const saltHex = arrayBufferToHex(saltBuffer);
  const saltAndPassword = await new Blob([
    hexToArrayBuffer(padHex(saltHex)),
    fullPasswordHash,
  ]).arrayBuffer();

  const x = await crypto.subtle.digest("SHA-256", saltAndPassword);

  // Get SRP constants
  const { g, N } = await getConstants();

  // Calculate the password verifier (g^x % N)
  const passwordVerifierBigInt = modPow(g, arrayBufferToBigInt(x), N);
  const passwordVerifierHex = padHex(passwordVerifierBigInt.toString(16));

  // Convert to the required format for Cognito
  const passwordVerifierBytes = hexToArrayBuffer(passwordVerifierHex);
  const passwordVerifier = bufferToBase64(passwordVerifierBytes);

  return {
    passwordVerifier,
    salt,
  };
}

// Result of SRP calculations for a device challenge
export interface DeviceSrpAuthResult {
  deviceGroupKey: string;
  srpAHex: string;
  passwordVerifier: string;
  passwordClaimSecretBlock: string;
  timestamp: string;
}

/**
 * Create a device handler for SRP authentication with a device
 * Used for DEVICE_SRP_AUTH and DEVICE_PASSWORD_VERIFIER challenges
 */
export async function createDeviceSrpAuthHandler(
  username: string,
  deviceKey: string
): Promise<
  | {
      deviceKey: string;
      handleDeviceSrpAuth: (
        srpB: string,
        secretBlock: string
      ) => Promise<DeviceSrpAuthResult>;
    }
  | undefined
> {
  const { debug, crypto } = configure();

  // Retrieve the device password - without this, we can't do device auth
  const devicePassword = await retrieveDevicePassword(deviceKey);
  if (!devicePassword) {
    debug?.(
      `No device password stored for device key ${deviceKey}, cannot create SRP handler`
    );
    return undefined;
  }

  // The device group key is typically the first part of the device key
  const deviceGroupKey = deviceKey.split("_")[0];

  return {
    deviceKey,
    handleDeviceSrpAuth: async (srpB: string, secretBlock: string) => {
      const timestamp = new Date().toISOString();

      try {
        // Following the Python example's SRP calculation pattern
        // Create FULL_PASSWORD = SHA256_HASH(DeviceGroupKey + deviceKey + ":" + DEVICE_PASSWORD)
        const fullPasswordString = `${deviceGroupKey}${deviceKey}:${devicePassword}`;
        const fullPasswordHash = await crypto.subtle.digest(
          "SHA-256",
          new TextEncoder().encode(fullPasswordString)
        );

        // Get SRP constants
        const { g, N, k } = await getConstants();

        // Generate a random 'a' value for SRP proof
        const aBytes = new Uint8Array(128);
        crypto.getRandomValues(aBytes);
        const a = arrayBufferToBigInt(aBytes) % N;

        // Calculate A = g^a % N
        const A = modPow(g, a, N);
        const srpAHex = padHex(A.toString(16));

        // SRP_B can be provided either as a hex string (common) or as base64.
        // Detect format and convert accordingly.
        let B: bigint;
        if (/^[0-9a-fA-F]+$/.test(srpB)) {
          // Hex-encoded
          B = BigInt(`0x${srpB}`);
        } else {
          // Assume base64
          B = BigInt(`0x${arrayBufferToHex(base64ToArrayBuffer(srpB))}`);
        }

        // Calculate u = H(A | B)
        const dataToHash = await new Blob([
          hexToArrayBuffer(padHex(srpAHex)),
          hexToArrayBuffer(padHex(B.toString(16))),
        ]).arrayBuffer();

        const uHash = await crypto.subtle.digest("SHA-256", dataToHash);
        const u = arrayBufferToBigInt(uHash);

        // Convert the password hash to a BigInt for the exponent
        const x = arrayBufferToBigInt(fullPasswordHash);

        // Calculate S = (B - kg^x)^(a + ux) % N
        const kgx = (k * modPow(g, x, N)) % N;
        const B_kgx = (B - kgx + N) % N; // Ensure positive value
        const a_ux = (a + u * x) % N;
        const S = modPow(B_kgx, a_ux, N);

        // Derive the authentication key K using the Cognito-specific HKDF:
        //   PRK = HMAC_SHA256(key = u, data = S)
        //   HKDF = HMAC_SHA256(key = PRK, data = "Caldera Derived Key" || 0x01)  → first 16 bytes
        const SHex = padHex(S.toString(16));
        const saltHkdfHex = padHex(arrayBufferToHex(uHash));

        // "Caldera Derived Key" concatenated with a single byte of value 1
        const infoBits = new Uint8Array(
          [..."Caldera Derived Key"].map((c) => c.charCodeAt(0)).concat([1])
        );

        const prkKey = await crypto.subtle.importKey(
          "raw",
          hexToArrayBuffer(saltHkdfHex),
          { name: "HMAC", hash: "SHA-256" },
          false,
          ["sign"]
        );
        const prk = await crypto.subtle.sign(
          "HMAC",
          prkKey,
          hexToArrayBuffer(SHex)
        );

        const hkdfKey = await crypto.subtle.importKey(
          "raw",
          prk,
          { name: "HMAC", hash: "SHA-256" },
          false,
          ["sign"]
        );
        const hkdf = (await crypto.subtle.sign("HMAC", hkdfKey, infoBits)).slice(0, 16);
        const K = hkdf;

        // Prepare the message to sign: deviceGroupKey + deviceKey + secretBlock + timestamp
        const message = deviceGroupKey + deviceKey + secretBlock + timestamp;
        const messageBuffer = new TextEncoder().encode(message);

        // Create HMAC using K as the key
        const hmacKey = await crypto.subtle.importKey(
          "raw",
          K,
          { name: "HMAC", hash: "SHA-256" },
          false,
          ["sign"]
        );

        const signatureBuffer = await crypto.subtle.sign(
          "HMAC",
          hmacKey,
          messageBuffer
        );

        // Base64 encode the signature
        const passwordVerifier = bufferToBase64(signatureBuffer);

        return {
          deviceGroupKey,
          srpAHex,
          passwordVerifier,
          passwordClaimSecretBlock: secretBlock,
          timestamp,
        };
      } catch (error) {
        debug?.("Error during device SRP calculation:", error);
        throw error;
      }
    },
  };
}

/**
 * Automatically handle device confirmation for authentication flows when NewDeviceMetadata is present.
 * This confirms the device using the device key provided in the authentication response.
 * We NEVER generate a device key - only use what Cognito provides.
 *
 * @param tokens The tokens from sign-in with newDeviceMetadata
 * @param deviceName Optional device name, defaults to auto-detected device type
 * @returns The updated tokens with deviceKey set and a userConfirmationNecessary flag
 */
export async function handleDeviceConfirmation(
  tokens: TokensFromSignIn,
  deviceName?: string
): Promise<TokensFromSignIn & { userConfirmationNecessary?: boolean }> {
  const { debug, userPoolId } = configure();

  debug?.("🔍 [Device Confirmation] Starting device confirmation process");

  // We MUST have newDeviceMetadata with a deviceKey to confirm a device
  if (!tokens.newDeviceMetadata?.deviceKey) {
    debug?.(
      "🔍 [Device Confirmation] No new device metadata present, skipping device confirmation"
    );
    return tokens;
  }

  const deviceKey = tokens.newDeviceMetadata.deviceKey;
  const deviceGroupKey = tokens.newDeviceMetadata.deviceGroupKey;
  debug?.(
    "🔍 [Device Confirmation] Device metadata received:",
    JSON.stringify({
      deviceKey,
      deviceGroupKey,
    })
  );

  // Validate device key format
  if (!deviceKey.includes("_")) {
    debug?.(
      "❌ [Device Confirmation] Invalid device key format (missing underscore): " +
        deviceKey
    );
    // Just return tokens without attempting confirmation
    tokens.deviceKey = deviceKey;
    return tokens;
  }

  // Extract and validate the region and UUID parts
  const [region, uuid] = deviceKey.split("_");
  debug?.(
    "🔍 [Device Confirmation] Device key components: region=" +
      region +
      ", uuid=" +
      uuid
  );

  if (!region || !uuid) {
    debug?.("❌ [Device Confirmation] Device key missing region or UUID part");
    tokens.deviceKey = deviceKey;
    return tokens;
  }

  if (!tokens.accessToken) {
    debug?.(
      "❌ [Device Confirmation] Missing access token required for device confirmation"
    );
    throw new Error("Missing access token required for device confirmation");
  }

  if (!userPoolId) {
    debug?.(
      "❌ [Device Confirmation] UserPoolId must be configured for device confirmation"
    );
    throw new Error("UserPoolId must be configured for device confirmation");
  }

  // Use provided name or detect device type
  const finalDeviceName = deviceName || getDeviceName();
  debug?.("🔍 [Device Confirmation] Using device name:", finalDeviceName);

  try {
    debug?.("🔍 [Device Confirmation] Generating device password");
    // Generate a device password and store it for future device auth
    const devicePassword = await generateDevicePassword();

    debug?.("🔍 [Device Confirmation] Storing device password");
    // Store the device password - we'll need this for device auth later
    await storeDevicePassword(deviceKey, devicePassword);

    debug?.("🔍 [Device Confirmation] Calculating device verifier using SRP");
    // Calculate device verifier using SRP
    const deviceVerifierConfig = await calculateDeviceVerifier(
      tokens.username,
      deviceKey,
      deviceGroupKey,
      devicePassword
    );

    debug?.(
      "🔍 [Device Confirmation] Device verifier config created using SRP calculation"
    );
    debug?.(
      "🔍 [Device Confirmation] Device verifier config:",
      deviceVerifierConfig
    );

    debug?.(
      "🔍 [Device Confirmation] Calling confirmDevice API with the device key"
    );
    debug?.(
      `🔍 [Device Confirmation] Access token length: ${tokens.accessToken.length}`
    );
    debug?.(`🔍 [Device Confirmation] Request details: 
      - deviceKey: ${deviceKey}
      - deviceName: ${finalDeviceName}
      - passwordVerifier length: ${deviceVerifierConfig.passwordVerifier.length}
      - salt length: ${deviceVerifierConfig.salt.length}
      - username: ${tokens.username}
    `);

    // Call confirmDevice with the device key
    const result = await confirmDevice({
      accessToken: tokens.accessToken,
      deviceKey,
      deviceName: finalDeviceName,
      deviceSecretVerifierConfig: deviceVerifierConfig,
    });

    debug?.(
      "✅ [Device Confirmation] Device confirmation successful, result:",
      JSON.stringify(result)
    );

    // Note whether user confirmation is necessary
    if (result.UserConfirmationNecessary) {
      debug?.(
        "🔍 [Device Confirmation] User confirmation necessary for device. Application should ask user if they want to remember this device."
      );
    } else {
      debug?.(
        "🔍 [Device Confirmation] Device automatically remembered based on user pool settings."
      );
    }

    // Set the deviceKey in the tokens
    tokens.deviceKey = deviceKey;

    debug?.(
      "🔍 [Device Confirmation] Storing device key and remembered status"
    );
    // Store the device key and remembered status
    await storeDeviceKey(deviceKey);
    await storeDeviceRememberedStatus(
      deviceKey,
      !result.UserConfirmationNecessary
    );

    debug?.(
      "✅ [Device Confirmation] Device confirmation completed successfully"
    );
    return {
      ...tokens,
      userConfirmationNecessary: result.UserConfirmationNecessary,
    };
  } catch (error) {
    debug?.(
      "❌ [Device Confirmation] Error during device confirmation:",
      error
    );
    const errorMsg = error instanceof Error ? error.message : String(error);
    debug?.(`❌ [Device Confirmation] Error details: ${errorMsg}`);
    // If device confirmation fails, we still set the deviceKey on the tokens object
    // for the current session, but DON'T store it in persistent storage
    // as it may be invalid for future authentication attempts
    tokens.deviceKey = deviceKey;
    return tokens;
  }
}

// Decode either standard Base-64 ( + / =) **or** URL-safe Base-64 ( - _ no padding )
function base64ToArrayBuffer(b64: string): ArrayBuffer {
  // Choose decoder based on character set to avoid throwing on malformed input
  const hasUrlSafeChars = /[-_]/.test(b64);

  // If padding is missing (common in URL-safe variant) add it so that length is a multiple of 4
  if (b64.length % 4 !== 0) {
    b64 += "===".slice(0, (4 - (b64.length % 4)) % 4);
  }

  return (hasUrlSafeChars ? bufferFromBase64Url(b64) : bufferFromBase64(b64)).buffer;
}
