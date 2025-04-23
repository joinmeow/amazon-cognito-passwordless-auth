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
import { configure, configureFromAmplify } from "./config.js";
import { CognitoSecurityProvider } from "./cognito-security.js";
import { signInWithLink } from "./magic-link.js";

// Helper to safely check browser environment without direct window reference
const isBrowser = () => typeof globalThis !== "undefined";
const getLocation = () => (isBrowser() ? globalThis.location : undefined);

// Initialize the security provider
if (isBrowser()) {
  // Create the instance but don't wait for it - it will initialize in the background
  void CognitoSecurityProvider.getInstance();
}

export function initialize(overrides?: Parameters<typeof configure>[0]) {
  configure(overrides);
  const location = getLocation();
  if (location && location.hash.indexOf("access_token") !== -1) {
    void signInWithLink()
      .signedIn.then(() => {
        location.replace(location.pathname + location.search);
      })
      .catch((err) => {
        console.error(err);
      });
  }
}

export const Passwordless = {
  configure,
  configureFromAmplify,
  security: {
    /**
     * Get the Cognito Security Provider instance
     */
    getSecurityProvider: () => CognitoSecurityProvider.getInstance(),
  },
};

// Re-export everything from the other modules
export * from "./common.js";
export * from "./fido2.js";
export * from "./magic-link.js";
export * from "./model.js";
export * from "./plaintext.js";
export * from "./refresh.js";
export * from "./srp.js";
export * from "./storage.js";
export * from "./util.js";
export * from "./jwt-model.js";
