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

import type { CognitoSecurityProvider } from "../cognito-security.js";
import type { configure } from "../config.js";

const SCRIPT_SELECTOR = 'script[src*="amazon-cognito-advanced-security"]';

type GlobalWithSecurityData = typeof globalThis & {
  AmazonCognitoAdvancedSecurityData?: {
    getData: (username: string, userPoolId: string, clientId: string) => string;
  };
};

/**
 * Load a fresh copy of the provider (it's a singleton with module state)
 * together with a fresh config module, then configure it.
 */
function loadProvider(
  config: Parameters<typeof configure>[0]
): CognitoSecurityProvider {
  let provider: CognitoSecurityProvider | undefined;
  jest.isolateModules(() => {
    /* eslint-disable @typescript-eslint/no-var-requires, @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-member-access, @typescript-eslint/no-unsafe-call */
    const configModule = require("../config.js");
    const securityModule = require("../cognito-security.js");
    configModule.configure(config);
    provider = securityModule.CognitoSecurityProvider.getInstance();
    /* eslint-enable @typescript-eslint/no-var-requires, @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-member-access, @typescript-eslint/no-unsafe-call */
  });
  if (!provider) {
    throw new Error("Failed to load CognitoSecurityProvider");
  }
  return provider;
}

function injectedScripts(): HTMLScriptElement[] {
  return Array.from(
    globalThis.document.querySelectorAll<HTMLScriptElement>(SCRIPT_SELECTOR)
  );
}

describe("CognitoSecurityProvider", () => {
  afterEach(() => {
    injectedScripts().forEach((script) => script.remove());
    delete (globalThis as GlobalWithSecurityData)
      .AmazonCognitoAdvancedSecurityData;
    jest.useRealTimers();
  });

  describe("when the security script cannot load (blocked / unreachable)", () => {
    it("resolves immediately with undefined, without waiting for the script", async () => {
      // Fake timers: if getSecurityData (still) waited on the old 5-second
      // Promise.race timeout, this await would never resolve and the test
      // would fail with a timeout.
      jest.useFakeTimers();
      const provider = loadProvider({
        clientId: "test-client-id",
        userPoolId: "us-east-1_abc123",
      });

      const data = await provider.getSecurityData("alice");

      expect(data).toBeUndefined();
    });

    it("injects the script at most once across multiple auth calls", async () => {
      const provider = loadProvider({
        clientId: "test-client-id",
        userPoolId: "us-east-1_abc123",
      });

      await provider.getSecurityData("alice");
      expect(injectedScripts()).toHaveLength(1);

      // Simulate the script failing to load (e.g. blocked by an ad blocker)
      injectedScripts()[0].onerror?.(new Event("error"));

      await provider.getSecurityData("alice");
      await provider.getSecurityData("alice");

      // No re-injection: still exactly one script tag
      expect(injectedScripts()).toHaveLength(1);
    });
  });

  describe("script injection region handling", () => {
    it("derives the region from a bare region endpoint", async () => {
      const provider = loadProvider({
        clientId: "test-client-id",
        userPoolId: "eu-west-1_abc123",
        cognitoIdpEndpoint: "eu-west-1",
      });

      await provider.getSecurityData("alice");

      const scripts = injectedScripts();
      expect(scripts).toHaveLength(1);
      expect(scripts[0].src).toBe(
        "https://amazon-cognito-assets.eu-west-1.amazoncognito.com/amazon-cognito-advanced-security-data.min.js"
      );
    });

    it("derives the region from a standard cognito-idp endpoint URL", async () => {
      const provider = loadProvider({
        clientId: "test-client-id",
        userPoolId: "eu-central-1_abc123",
        cognitoIdpEndpoint: "https://cognito-idp.eu-central-1.amazonaws.com",
      });

      await provider.getSecurityData("alice");

      const scripts = injectedScripts();
      expect(scripts).toHaveLength(1);
      expect(scripts[0].src).toContain("amazon-cognito-assets.eu-central-1");
    });

    it("does not inject (nor default to us-east-1) for custom proxy endpoints", async () => {
      const provider = loadProvider({
        clientId: "test-client-id",
        userPoolId: "us-east-1_abc123",
        cognitoIdpEndpoint: "https://auth-proxy.example.com",
      });

      const data = await provider.getSecurityData("alice");

      expect(data).toBeUndefined();
      expect(injectedScripts()).toHaveLength(0);
    });

    it("does not inject for regions where the script is not hosted", async () => {
      const provider = loadProvider({
        clientId: "test-client-id",
        userPoolId: "ap-southeast-1_abc123",
        cognitoIdpEndpoint: "ap-southeast-1",
      });

      const data = await provider.getSecurityData("alice");

      expect(data).toBeUndefined();
      expect(injectedScripts()).toHaveLength(0);
    });

    it("prefers the configured advancedSecurity.region over the endpoint-derived region", async () => {
      const provider = loadProvider({
        clientId: "test-client-id",
        userPoolId: "eu-west-1_abc123",
        cognitoIdpEndpoint: "eu-west-1",
        advancedSecurity: { region: "us-west-2" },
      });

      await provider.getSecurityData("alice");

      const scripts = injectedScripts();
      expect(scripts).toHaveLength(1);
      expect(scripts[0].src).toContain("amazon-cognito-assets.us-west-2");
    });

    it("uses the configured advancedSecurity.region for custom proxy endpoints", async () => {
      const provider = loadProvider({
        clientId: "test-client-id",
        userPoolId: "us-east-1_abc123",
        cognitoIdpEndpoint: "https://auth-proxy.example.com",
        advancedSecurity: { region: "us-east-1" },
      });

      await provider.getSecurityData("alice");

      const scripts = injectedScripts();
      expect(scripts).toHaveLength(1);
      expect(scripts[0].src).toBe(
        "https://amazon-cognito-assets.us-east-1.amazoncognito.com/amazon-cognito-advanced-security-data.min.js"
      );
    });

    it("does not inject when the configured advancedSecurity.region is not where the script is hosted", async () => {
      const provider = loadProvider({
        clientId: "test-client-id",
        userPoolId: "us-east-1_abc123",
        cognitoIdpEndpoint: "https://auth-proxy.example.com",
        advancedSecurity: { region: "ap-southeast-1" },
      });

      const data = await provider.getSecurityData("alice");

      expect(data).toBeUndefined();
      expect(injectedScripts()).toHaveLength(0);
    });
  });

  describe("when script injection fails synchronously", () => {
    it("retries injection on a later call when appending the script throws", async () => {
      const provider = loadProvider({
        clientId: "test-client-id",
        userPoolId: "us-east-1_abc123",
      });
      const appendSpy = jest
        .spyOn(globalThis.document.head, "appendChild")
        .mockImplementationOnce(() => {
          throw new Error("blocked by CSP");
        });

      // First call: injection fails synchronously, auth call is not blocked
      expect(await provider.getSecurityData("alice")).toBeUndefined();
      expect(injectedScripts()).toHaveLength(0);

      appendSpy.mockRestore();

      // Next call: injection is retried and succeeds
      expect(await provider.getSecurityData("alice")).toBeUndefined();
      expect(injectedScripts()).toHaveLength(1);

      // After a successful injection, it is still injected at most once
      await provider.getSecurityData("alice");
      expect(injectedScripts()).toHaveLength(1);
    });
  });

  describe("when the security script global is present", () => {
    it("returns the encoded data without injecting a script", async () => {
      const getData = jest.fn().mockReturnValue("encoded-security-data");
      (globalThis as GlobalWithSecurityData).AmazonCognitoAdvancedSecurityData =
        { getData };
      const provider = loadProvider({
        clientId: "test-client-id",
        userPoolId: "us-east-1_abc123",
      });

      const data = await provider.getSecurityData("alice");

      expect(data).toBe("encoded-security-data");
      expect(getData).toHaveBeenCalledWith(
        "alice",
        "us-east-1_abc123",
        "test-client-id"
      );
      expect(injectedScripts()).toHaveLength(0);
    });

    it("returns the encoded data when the script finishes loading after injection", async () => {
      const provider = loadProvider({
        clientId: "test-client-id",
        userPoolId: "us-east-1_abc123",
      });

      // First call: script not loaded yet, data omitted
      expect(await provider.getSecurityData("alice")).toBeUndefined();
      expect(injectedScripts()).toHaveLength(1);

      // Simulate the injected script finishing loading
      (globalThis as GlobalWithSecurityData).AmazonCognitoAdvancedSecurityData =
        { getData: () => "late-loaded-data" };
      injectedScripts()[0].onload?.(new Event("load"));

      expect(await provider.getSecurityData("alice")).toBe("late-loaded-data");
      expect(injectedScripts()).toHaveLength(1);
    });
  });
});
