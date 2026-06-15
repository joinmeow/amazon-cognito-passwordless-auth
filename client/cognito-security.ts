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

// The Amazon Cognito Advanced Security script is only hosted in these regions
const SUPPORTED_SCRIPT_REGIONS = [
  "us-east-1",
  "us-east-2",
  "us-west-2",
  "eu-west-1",
  "eu-west-2",
  "eu-central-1",
];

// A well-formed AWS region identifier, covering partitioned/multi-segment
// regions (us-gov-west-1, eusc-de-east-1). Two alternatives instead of a
// nested quantifier to satisfy the security/detect-unsafe-regex lint rule.
// Crucially this contains no "." or "/", so it cannot express a host other
// than amazon-cognito-assets.<region>.amazoncognito.com when interpolated
// into the script URL — a value like "us-east-1.evil.com/x" is rejected.
const AWS_REGION_FORMAT = /^[a-z]{2,4}-[a-z]+-\d$|^[a-z]{2,4}-[a-z]+-[a-z]+-\d$/;

/**
 * Manages the Amazon Cognito Advanced Security data collection
 */
export class CognitoSecurityProvider {
  private static instance: CognitoSecurityProvider;
  private scriptInjectionAttempted = false;
  // The region we last declined to inject for (unsupported / undetermined).
  // Tracked so a later configure() that supplies a usable region re-attempts
  // injection instead of being permanently latched, while repeated auth
  // calls for the same skipped region don't re-log.
  private skippedForRegion: string | undefined;

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
   * Determine the region to load the security script from, based on the
   * configured Cognito IDP endpoint. Only used when no explicit
   * advancedSecurity.region is configured. Returns undefined if the region
   * cannot be determined (e.g. a custom proxy endpoint).
   */
  private resolveScriptRegion(cognitoIdpEndpoint: string): string | undefined {
    if (/^[a-z]{2}-[a-z]+-\d+$/.test(cognitoIdpEndpoint)) {
      return cognitoIdpEndpoint;
    }
    const urlMatch = cognitoIdpEndpoint.match(
      /^https:\/\/cognito-idp\.([a-z]{2}-[a-z]+-\d+)\.amazonaws\.com\/?$/
    );
    return urlMatch?.[1];
  }

  /**
   * Initialize the security provider by injecting the Amazon Cognito
   * Advanced Security script, if it isn't already present.
   *
   * This is fire-and-forget: it never waits for the script to load (auth
   * calls must not block on it) and injection is attempted at most once per
   * page load — a later call only retries if the injection itself failed
   * synchronously (e.g. no DOM available yet, or appendChild threw). If the
   * script isn't (yet) available, security data is simply omitted from auth
   * calls — same behavior as AWS's own libraries.
   */
  public async initialize(): Promise<void> {
    if (this.scriptInjectionAttempted) {
      return;
    }

    const win = getWindow();
    if (!win) {
      return;
    }

    const { debug, cognitoIdpEndpoint, advancedSecurity } = configure();

    // Check if script is already loaded (e.g. included by the application)
    if (typeof win.AmazonCognitoAdvancedSecurityData !== "undefined") {
      this.scriptInjectionAttempted = true;
      debug?.(
        "CognitoSecurityProvider: Amazon Cognito Advanced Security already available"
      );
      return;
    }

    // Prefer the explicitly configured script region (e.g. for custom proxy
    // endpoints), and only fall back to parsing the Cognito IDP endpoint.
    const explicitRegion = advancedSecurity?.region;

    // An explicit region is interpolated into the script host. It must be a
    // well-formed region token, NOT just any non-empty string: otherwise a
    // value sourced from deployment/tenant data like "us-east-1.evil.com/x"
    // would load the script from an attacker-controlled host. Reject a
    // malformed explicit region outright rather than fall through to the
    // endpoint-derived region (which would mask the misconfiguration).
    if (explicitRegion && !AWS_REGION_FORMAT.test(explicitRegion)) {
      const skipKey = `invalid:${explicitRegion}`;
      if (this.skippedForRegion !== skipKey) {
        this.skippedForRegion = skipKey;
        debug?.(
          `CognitoSecurityProvider: advancedSecurity.region "${explicitRegion}" is not a valid AWS region identifier, skipping script injection`
        );
      }
      return;
    }

    const region =
      explicitRegion ?? this.resolveScriptRegion(cognitoIdpEndpoint);

    // A well-formed, explicitly configured advancedSecurity.region is an
    // operator opt-in and is trusted even if it is not in the (hardcoded,
    // necessarily incomplete) allowlist — e.g. pointing a pool whose own
    // region does not host the script at a region that does (us-east-1's
    // script is region-generic). The allowlist only filters the
    // AUTO-RESOLVED region, to avoid a guaranteed 404 from loading the
    // script for a region known not to host it.
    const usable =
      !!region &&
      (!!explicitRegion || SUPPORTED_SCRIPT_REGIONS.includes(region));

    if (!usable) {
      // Do NOT permanently latch scriptInjectionAttempted here: a later
      // configure() that supplies a usable advancedSecurity.region must be
      // able to re-attempt injection. Dedupe the log per distinct skipped
      // region so repeated auth calls don't spam it.
      const skipKey = region ?? "<undetermined>";
      if (this.skippedForRegion !== skipKey) {
        this.skippedForRegion = skipKey;
        debug?.(
          region
            ? `CognitoSecurityProvider: Security script not hosted in region ${region} and no advancedSecurity.region override set, skipping script injection`
            : `CognitoSecurityProvider: Cannot determine security script region for endpoint ${cognitoIdpEndpoint} (set advancedSecurity.region to override), skipping script injection`
        );
      }
      return;
    }
    this.skippedForRegion = undefined;

    const doc = getDocument();
    if (!doc) {
      // No DOM available (yet); leave the flag unset so a later
      // initialize() call can retry
      return;
    }

    debug?.(
      `CognitoSecurityProvider: Loading security script for region ${region}`
    );

    try {
      // Create script element
      const script = doc.createElement("script");
      script.src = `https://amazon-cognito-assets.${region}.amazoncognito.com/amazon-cognito-advanced-security-data.min.js`;
      script.async = true;
      script.onload = () => {
        debug?.("CognitoSecurityProvider: Security script loaded successfully");
      };
      script.onerror = () => {
        debug?.(
          `CognitoSecurityProvider: Failed to load Amazon Cognito Advanced Security script for region ${region}`
        );
      };

      // Append script to document, without waiting for it to load. Only
      // latch the flag once injection actually succeeded, so a synchronous
      // failure (e.g. CSP blocking appendChild) doesn't prevent a retry
      doc.head.appendChild(script);
      this.scriptInjectionAttempted = true;
    } catch (error) {
      debug?.(
        "CognitoSecurityProvider: Failed to inject security script, will retry on next call:",
        error
      );
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

    if (!win || !win.AmazonCognitoAdvancedSecurityData) {
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
   * Ensures the security provider is initialized and returns encoded data.
   * Never blocks on script loading: if the script isn't (yet) available,
   * this resolves immediately with undefined.
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
