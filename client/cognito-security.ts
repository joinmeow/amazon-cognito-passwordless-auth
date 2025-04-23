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

// Define interfaces for global objects
interface CognitoWindow {
  AmazonCognitoAdvancedSecurityData?: {
    getData: (username: string, userPoolId: string, clientId: string) => string;
  };
}

type BrowserGlobal = typeof globalThis & {
  document?: Document;
};

// Helper function to safely check if we're in a browser environment
const isBrowser = (): boolean =>
  typeof globalThis !== "undefined" && !!(globalThis as BrowserGlobal).document;

// Safe access to global browser objects
const getWindow = (): (CognitoWindow & typeof globalThis) | undefined =>
  isBrowser() ? (globalThis as CognitoWindow & typeof globalThis) : undefined;

const getDocument = (): Document | undefined =>
  isBrowser() ? (globalThis as BrowserGlobal).document : undefined;

/**
 * Manages the Amazon Cognito Advanced Security data collection
 */
export class CognitoSecurityProvider {
  private static instance: CognitoSecurityProvider;
  private initialized = false;
  private scriptLoaded = false;
  private scriptLoading = false;

  // Private constructor for singleton
  private constructor() {}

  /**
   * Get the singleton instance
   */
  public static getInstance(): CognitoSecurityProvider {
    if (!CognitoSecurityProvider.instance) {
      CognitoSecurityProvider.instance = new CognitoSecurityProvider();
    }
    return CognitoSecurityProvider.instance;
  }

  /**
   * Initialize the security provider
   */
  public async initialize(): Promise<void> {
    if (this.initialized || this.scriptLoading) {
      return;
    }

    const { debug } = configure();
    const win = getWindow();

    if (!win) {
      debug?.(
        "CognitoSecurityProvider: Window not available, skipping initialization"
      );
      return;
    }

    // Check if script is already loaded
    if (typeof win.AmazonCognitoAdvancedSecurityData !== "undefined") {
      this.scriptLoaded = true;
      this.initialized = true;
      debug?.(
        "CognitoSecurityProvider: Amazon Cognito Advanced Security already available"
      );
      return;
    }

    const { cognitoIdpEndpoint } = configure();
    // Extract region from endpoint or use default region
    const regionMatch = cognitoIdpEndpoint.match(/^[a-z]{2}-[a-z]+-\d$/);
    const region = regionMatch ? cognitoIdpEndpoint : "us-east-1";

    try {
      this.scriptLoading = true;
      debug?.(
        `CognitoSecurityProvider: Loading security script for region ${region}`
      );

      const doc = getDocument();
      if (!doc) {
        throw new Error("Document not available");
      }

      // Create script element
      const script = doc.createElement("script");
      script.src = `https://amazon-cognito-assets.${region}.amazoncognito.com/amazon-cognito-advanced-security-data.min.js`;
      script.async = true;

      // Create promise to track script loading
      const scriptLoadPromise = new Promise<void>((resolve, reject) => {
        script.onload = () => {
          this.scriptLoaded = true;
          this.initialized = true;
          debug?.(
            "CognitoSecurityProvider: Security script loaded successfully"
          );
          resolve();
        };

        script.onerror = () => {
          const error = new Error(
            `Failed to load Amazon Cognito Advanced Security script for region ${region}`
          );
          debug?.("CognitoSecurityProvider:", error);
          reject(error);
        };
      });

      // Append script to document
      doc.head.appendChild(script);

      // Wait for script to load with timeout
      const timeoutPromise = new Promise<void>((_, reject) => {
        setTimeout(() => {
          reject(new Error("Security script loading timed out after 5000ms"));
        }, 5000);
      });

      await Promise.race([scriptLoadPromise, timeoutPromise]);
    } catch (error) {
      debug?.(
        "CognitoSecurityProvider: Error initializing security script:",
        error
      );
    } finally {
      this.scriptLoading = false;
    }
  }

  /**
   * Get the encoded security data for the given user
   */
  public getEncodedData(username: string): string | undefined {
    const { clientId, userPoolId, debug } = configure();
    const win = getWindow();

    if (!userPoolId) {
      debug?.(
        "CognitoSecurityProvider: Missing userPoolId, cannot generate security data"
      );
      return undefined;
    }

    if (!this.scriptLoaded || !win || !win.AmazonCognitoAdvancedSecurityData) {
      debug?.(
        "CognitoSecurityProvider: Security script not loaded, cannot generate security data"
      );
      return undefined;
    }

    try {
      return win.AmazonCognitoAdvancedSecurityData.getData(
        username,
        userPoolId,
        clientId
      );
    } catch (error) {
      debug?.(
        "CognitoSecurityProvider: Error generating security data:",
        error
      );
      return undefined;
    }
  }

  /**
   * Ensures the security provider is initialized and returns encoded data
   */
  public async getSecurityData(username: string): Promise<string | undefined> {
    await this.initialize();
    return this.getEncodedData(username);
  }
}

// Immediately initialize the provider in browser environments
if (isBrowser()) {
  // Don't await - let it initialize in the background
  CognitoSecurityProvider.getInstance()
    .initialize()
    .catch(() => {
      // Errors are already logged in the provider
    });
}
