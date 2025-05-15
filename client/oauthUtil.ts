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

/** Generate cryptographically secure random hex string */
export function generateRandomString(length: number): string {
  const crypto = configure().crypto;
  const array = new Uint8Array(length);
  crypto.getRandomValues(array);
  return Array.from(array)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

function urlSafeBase64(buffer: ArrayBuffer): string {
  const str = String.fromCharCode(...new Uint8Array(buffer));
  return btoa(str).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** Generate PKCE verifier and challenge */
export async function generatePkcePair(): Promise<{
  verifier: string;
  challenge: string;
  method: "S256";
}> {
  const verifier = generateRandomString(64);
  const crypto = configure().crypto;
  const data = new TextEncoder().encode(verifier);
  const hash = await crypto.subtle.digest("SHA-256", data);
  const challenge = urlSafeBase64(hash);
  return { verifier, challenge, method: "S256" };
}
