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

import { signOutWithRedirect } from "../hosted-oauth.js";
import { configure, getLogoutEndpoint } from "../config.js";
import { signOut } from "../common.js";
import type { Config } from "../config.js";

// Mock the local sign-out (the real config module is used so we exercise
// actual logout URL construction)
jest.mock("../common");
jest.mock("../storage");

const mockSignOut = signOut as jest.MockedFunction<typeof signOut>;

type MutableLocation = {
  href: string;
  hostname: string;
};

describe("Hosted UI logout (signOutWithRedirect)", () => {
  let mockLocation: MutableLocation;
  let mockStorage: {
    getItem: jest.Mock;
    setItem: jest.Mock;
    removeItem: jest.Mock;
  };

  const baseConfig = (): Config => ({
    cognitoIdpEndpoint: "eu-west-1",
    clientId: "test-client-id",
    hostedUi: {
      domain: "auth.example.com",
      redirectSignIn: "https://app.example.com/signin-redirect",
      redirectSignOut: "https://app.example.com/signed-out",
    },
    location: mockLocation,
    storage: mockStorage,
  });

  beforeEach(() => {
    jest.clearAllMocks();

    mockLocation = {
      href: "https://app.example.com/some/page",
      hostname: "app.example.com",
    };

    mockStorage = {
      getItem: jest.fn(),
      setItem: jest.fn(),
      removeItem: jest.fn(),
    };

    mockSignOut.mockReturnValue({
      signedOut: Promise.resolve(),
      abort: jest.fn(),
    } as unknown as ReturnType<typeof signOut>);
  });

  describe("getLogoutEndpoint", () => {
    it("builds the logout endpoint from the hosted UI domain", () => {
      configure(baseConfig());
      expect(getLogoutEndpoint()).toBe("https://auth.example.com/logout");
    });

    it("falls back to cognitoIdpEndpoint when no hosted UI domain is set", () => {
      const config = baseConfig();
      config.cognitoIdpEndpoint = "https://cognito.example.com";
      delete config.hostedUi!.domain;
      configure(config);
      expect(getLogoutEndpoint()).toBe("https://cognito.example.com/logout");
    });
  });

  describe("signOutWithRedirect", () => {
    it("navigates to the logout endpoint with client_id and encoded logout_uri", async () => {
      configure(baseConfig());

      await signOutWithRedirect();

      expect(mockLocation.href).toBe(
        "https://auth.example.com/logout?client_id=test-client-id&logout_uri=https%3A%2F%2Fapp.example.com%2Fsigned-out"
      );
    });

    it("converts a relative redirectSignOut to an absolute logout_uri", async () => {
      const config = baseConfig();
      config.hostedUi!.redirectSignOut = "/signed-out";
      configure(config);

      await signOutWithRedirect();

      expect(mockLocation.href).toBe(
        "https://auth.example.com/logout?client_id=test-client-id&logout_uri=https%3A%2F%2Fapp.example.com%2Fsigned-out"
      );
    });

    it("performs the local sign-out before navigating", async () => {
      const events: string[] = [];

      mockSignOut.mockReturnValue({
        signedOut: new Promise<void>((resolve) => {
          setTimeout(() => {
            events.push("localSignOut");
            resolve();
          }, 10);
        }),
        abort: jest.fn(),
      } as unknown as ReturnType<typeof signOut>);

      let href = "https://app.example.com/some/page";
      const trackedLocation: MutableLocation = {
        hostname: "app.example.com",
        get href() {
          return href;
        },
        set href(value: string) {
          events.push("navigate");
          href = value;
        },
      };
      const config = baseConfig();
      config.location = trackedLocation;
      configure(config);

      await signOutWithRedirect();

      expect(events).toEqual(["localSignOut", "navigate"]);
    });

    it("forwards sign-out props (e.g. skipTokenRevocation) to the local signOut", async () => {
      configure(baseConfig());
      const tokensRemovedLocallyCb = jest.fn();

      await signOutWithRedirect({
        skipTokenRevocation: true,
        tokensRemovedLocallyCb,
      });

      expect(mockSignOut).toHaveBeenCalledWith({
        skipTokenRevocation: true,
        tokensRemovedLocallyCb,
      });
    });

    it("throws and does not navigate when redirectSignOut is not configured", async () => {
      const config = baseConfig();
      delete config.hostedUi!.redirectSignOut;
      configure(config);

      await expect(signOutWithRedirect()).rejects.toThrow(
        "hostedUi.redirectSignOut configuration missing"
      );
      expect(mockSignOut).not.toHaveBeenCalled();
      expect(mockLocation.href).toBe("https://app.example.com/some/page");
    });

    it("throws and does not navigate when hostedUi is not configured", async () => {
      const config = baseConfig();
      delete config.hostedUi;
      configure(config);

      await expect(signOutWithRedirect()).rejects.toThrow(
        "hostedUi configuration missing"
      );
      expect(mockSignOut).not.toHaveBeenCalled();
      expect(mockLocation.href).toBe("https://app.example.com/some/page");
    });

    it("does not navigate when the local sign-out fails", async () => {
      configure(baseConfig());

      mockSignOut.mockReturnValue({
        signedOut: Promise.reject(new Error("sign-out failed")),
        abort: jest.fn(),
      } as unknown as ReturnType<typeof signOut>);

      await expect(signOutWithRedirect()).rejects.toThrow("sign-out failed");
      expect(mockLocation.href).toBe("https://app.example.com/some/page");
    });
  });
});
