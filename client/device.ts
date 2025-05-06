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

import { bufferToBase64 } from "./util.js";
import {
  modPow,
  getConstants,
  hexToArrayBuffer,
  arrayBufferToHex,
  arrayBufferToBigInt,
  padHex,
} from "./srp.js";
import { TokensFromSignIn } from "./model.js";
import { storeDeviceKey, storeDeviceRememberedStatus } from "./storage.js";
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
  const { debug, crypto, userPoolId } = configure();

  // We MUST have newDeviceMetadata with a deviceKey to confirm a device
  if (!tokens.newDeviceMetadata?.deviceKey) {
    debug?.("No new device metadata present, skipping device confirmation");
    return tokens;
  }

  const deviceKey = tokens.newDeviceMetadata.deviceKey;
  const deviceGroupKey = tokens.newDeviceMetadata.deviceGroupKey;
  debug?.(
    "Device metadata received:",
    JSON.stringify({
      deviceKey,
      deviceGroupKey,
    })
  );

  if (!tokens.accessToken) {
    throw new Error("Missing access token required for device confirmation");
  }

  if (!userPoolId) {
    throw new Error("UserPoolId must be configured for device confirmation");
  }

  // Use provided name or detect device type
  const finalDeviceName = deviceName || getDeviceName();
  debug?.("Using device name:", finalDeviceName);

  try {
    // Generate salt
    const saltBuffer = new Uint8Array(16);
    crypto.getRandomValues(saltBuffer);
    // Ensure first bit is not set (making it positive)
    saltBuffer[0] = saltBuffer[0] & 0x7f;
    const salt = bufferToBase64(saltBuffer);

    // Generate a random 40-byte password
    const randomPasswordBuffer = new Uint8Array(40);
    crypto.getRandomValues(randomPasswordBuffer);
    const randomPassword = bufferToBase64(randomPasswordBuffer);

    const username = tokens.username;

    // Create FULL_PASSWORD = SHA256_HASH(DeviceGroupKey + username + ":" + RANDOM_PASSWORD)
    const fullPasswordString = `${deviceGroupKey}${username}:${randomPassword}`;
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

    // Calculate the password verifier
    // PasswordVerifier = g^x % N
    const passwordVerifierBigInt = modPow(g, arrayBufferToBigInt(x), N);
    const passwordVerifierHex = padHex(passwordVerifierBigInt.toString(16));

    // Convert to the required format for Cognito
    const passwordVerifierBytes = hexToArrayBuffer(passwordVerifierHex);
    const passwordVerifier = bufferToBase64(passwordVerifierBytes);

    debug?.("Device verifier config created using SRP calculation");

    // Create device verifier config
    const deviceVerifierConfig = {
      passwordVerifier,
      salt,
    };

    debug?.("Device verifier config:", deviceVerifierConfig);

    // Call confirmDevice with the device key
    const result = await confirmDevice({
      accessToken: tokens.accessToken,
      deviceKey,
      deviceName: finalDeviceName,
      deviceSecretVerifierConfig: deviceVerifierConfig,
    });

    debug?.("Device confirmation successful, result:", JSON.stringify(result));

    // Note whether user confirmation is necessary
    if (result.UserConfirmationNecessary) {
      debug?.(
        "User confirmation necessary for device. Application should ask user if they want to remember this device."
      );
    } else {
      debug?.("Device automatically remembered based on user pool settings.");
    }

    // Set the deviceKey in the tokens
    tokens.deviceKey = deviceKey;

    // Store the device key and remembered status
    await storeDeviceKey(deviceKey);
    await storeDeviceRememberedStatus(deviceKey, !result.UserConfirmationNecessary);

    debug?.("Device confirmation completed successfully");
    return {
      ...tokens,
      userConfirmationNecessary: result.UserConfirmationNecessary,
    };
  } catch (error) {
    debug?.("Error during device confirmation:", error);
    // If device confirmation fails, we still set the deviceKey on the tokens object
    // for the current session, but DON'T store it in persistent storage
    // as it may be invalid for future authentication attempts
    tokens.deviceKey = deviceKey;
    return tokens;
  }
}
