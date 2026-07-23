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

import {
  configure,
  getAuthorizeEndpoint,
  getTokenEndpoint,
} from "../config.js";

describe("OAuth2 endpoints (Hosted UI domain)", () => {
  const redirectSignIn = "https://app.example.com/signin-redirect";

  describe("configure", () => {
    it("throws when hostedUi is configured without domain and cognitoIdpEndpoint is a region", () => {
      expect(() =>
        configure({
          cognitoIdpEndpoint: "eu-west-1",
          clientId: "test-client-id",
          hostedUi: {
            redirectSignIn,
          },
        })
      ).toThrow("hostedUi.domain is required");
    });

    it("throws when hostedUi.domain uses plaintext http://", () => {
      // The domain becomes the OAuth2 base that codes/tokens travel to, so
      // it must be https:// (mirrors the cognitoIdpEndpoint http:// rejection)
      expect(() =>
        configure({
          cognitoIdpEndpoint: "eu-west-1",
          clientId: "test-client-id",
          hostedUi: {
            domain: "http://auth.example.com",
            redirectSignIn,
          },
        })
      ).toThrow("hostedUi.domain must not use plaintext http://");
    });

    it("accepts a bare hostedUi.domain (https:// is assumed)", () => {
      configure({
        cognitoIdpEndpoint: "eu-west-1",
        clientId: "test-client-id",
        hostedUi: {
          domain: "example.auth.eu-west-1.amazoncognito.com",
          redirectSignIn,
        },
      });
      expect(getAuthorizeEndpoint()).toBe(
        "https://example.auth.eu-west-1.amazoncognito.com/oauth2/authorize"
      );
    });

    it("throws when hostedUi is configured without domain and cognitoIdpEndpoint is an https:// prefixed region", () => {
      // https://eu-west-1 is not a usable OAuth2 origin: it is just the bare
      // AWS region with a scheme glued on, not a real custom URL
      const previous = configure({
        cognitoIdpEndpoint: "eu-west-1",
        clientId: "previous-client-id",
      });
      expect(() =>
        configure({
          cognitoIdpEndpoint: "https://eu-west-1",
          clientId: "rejected-client-id",
          hostedUi: {
            redirectSignIn,
          },
        })
      ).toThrow("hostedUi.domain is required");
      // The failed configure() must not have touched the loaded configuration
      const current = configure();
      expect(current).toBe(previous);
      expect(current.clientId).toBe("previous-client-id");
    });

    it("throws when hostedUi is configured without domain and cognitoIdpEndpoint is an https:// dotless host", () => {
      expect(() =>
        configure({
          cognitoIdpEndpoint: "https://localhost",
          clientId: "test-client-id",
          hostedUi: {
            redirectSignIn,
          },
        })
      ).toThrow("hostedUi.domain is required");
    });

    it("throws when hostedUi is configured without domain and cognitoIdpEndpoint is derived from userPoolId", () => {
      expect(() =>
        configure({
          userPoolId: "eu-west-1_abc123",
          clientId: "test-client-id",
          hostedUi: {
            redirectSignIn,
          },
        })
      ).toThrow("hostedUi.domain is required");
    });

    it("accepts hostedUi without domain when cognitoIdpEndpoint is a full custom URL", () => {
      const config = configure({
        cognitoIdpEndpoint: "https://cognito-proxy.example.com",
        clientId: "test-client-id",
        hostedUi: {
          redirectSignIn,
        },
      });
      expect(config.hostedUi?.domain).toBeUndefined();
    });

    it("throws when cognitoIdpEndpoint is a plaintext http:// URL", () => {
      // Passwords, SRP parameters and refresh/access tokens are POSTed to this
      // endpoint, so a plaintext http:// endpoint is rejected outright at
      // configure() time — before any hostedUi.domain validation is reached
      expect(() =>
        configure({
          cognitoIdpEndpoint: "http://cognito-proxy.example.com",
          clientId: "test-client-id",
          hostedUi: {
            redirectSignIn,
          },
        })
      ).toThrow("cognitoIdpEndpoint must not use plaintext http://");
    });

    it("accepts an https:// cognitoIdpEndpoint", () => {
      const config = configure({
        cognitoIdpEndpoint: "https://cognito-proxy.example.com",
        clientId: "test-client-id",
      });
      expect(config.cognitoIdpEndpoint).toBe(
        "https://cognito-proxy.example.com"
      );
    });

    it("accepts a bare AWS region cognitoIdpEndpoint (not rejected as http://)", () => {
      const config = configure({
        cognitoIdpEndpoint: "eu-west-1",
        clientId: "test-client-id",
      });
      expect(config.cognitoIdpEndpoint).toBe("eu-west-1");
    });

    it("leaves the previous configuration intact when configure() throws", () => {
      const previous = configure({
        cognitoIdpEndpoint: "eu-west-1",
        clientId: "previous-client-id",
      });
      expect(() =>
        configure({
          cognitoIdpEndpoint: "eu-west-1",
          clientId: "rejected-client-id",
          hostedUi: {
            redirectSignIn,
          },
        })
      ).toThrow("hostedUi.domain is required");
      const current = configure();
      expect(current).toBe(previous);
      expect(current.clientId).toBe("previous-client-id");
      expect(current.hostedUi).toBeUndefined();
    });

    it("accepts hostedUi with domain when cognitoIdpEndpoint is a region", () => {
      const config = configure({
        cognitoIdpEndpoint: "eu-west-1",
        clientId: "test-client-id",
        hostedUi: {
          domain: "example.auth.eu-west-1.amazoncognito.com",
          redirectSignIn,
        },
      });
      expect(config.hostedUi?.domain).toBe(
        "example.auth.eu-west-1.amazoncognito.com"
      );
    });
  });

  describe("getAuthorizeEndpoint / getTokenEndpoint", () => {
    it("builds endpoints from hostedUi.domain", () => {
      configure({
        cognitoIdpEndpoint: "eu-west-1",
        clientId: "test-client-id",
        hostedUi: {
          domain: "example.auth.eu-west-1.amazoncognito.com",
          redirectSignIn,
        },
      });
      expect(getAuthorizeEndpoint()).toBe(
        "https://example.auth.eu-west-1.amazoncognito.com/oauth2/authorize"
      );
      expect(getTokenEndpoint()).toBe(
        "https://example.auth.eu-west-1.amazoncognito.com/oauth2/token"
      );
    });

    it("builds endpoints from a custom domain with protocol and trailing slash", () => {
      configure({
        cognitoIdpEndpoint: "eu-west-1",
        clientId: "test-client-id",
        hostedUi: {
          domain: "https://auth.example.com/",
          redirectSignIn,
        },
      });
      expect(getAuthorizeEndpoint()).toBe(
        "https://auth.example.com/oauth2/authorize"
      );
      expect(getTokenEndpoint()).toBe("https://auth.example.com/oauth2/token");
    });

    it("falls back to cognitoIdpEndpoint only when it is a full custom URL", () => {
      configure({
        cognitoIdpEndpoint: "https://cognito-proxy.example.com/",
        clientId: "test-client-id",
        hostedUi: {
          redirectSignIn,
        },
      });
      expect(getAuthorizeEndpoint()).toBe(
        "https://cognito-proxy.example.com/oauth2/authorize"
      );
      expect(getTokenEndpoint()).toBe(
        "https://cognito-proxy.example.com/oauth2/token"
      );
    });

    it("refuses a plaintext http:// cognitoIdpEndpoint at configure() time", () => {
      // A non-TLS origin is rejected outright by configure(), so the OAuth2
      // endpoints can never be built on it — authorization codes, tokens,
      // passwords and SRP parameters all travel to this origin
      expect(() =>
        configure({
          cognitoIdpEndpoint: "http://cognito-proxy.example.com",
          clientId: "test-client-id",
        })
      ).toThrow("cognitoIdpEndpoint must not use plaintext http://");
    });

    it("never produces https://<region>/oauth2/... for a region-only cognitoIdpEndpoint", () => {
      // hostedUi is not configured here, so configure() succeeds; the
      // endpoint getters must still refuse to build a garbage URL
      configure({
        cognitoIdpEndpoint: "eu-west-1",
        clientId: "test-client-id",
      });
      expect(() => getAuthorizeEndpoint()).toThrow(
        "Cannot determine OAuth2 endpoint"
      );
      expect(() => getTokenEndpoint()).toThrow(
        "Cannot determine OAuth2 endpoint"
      );
    });

    it("never produces https://<region>/oauth2/... for an https:// prefixed region cognitoIdpEndpoint", () => {
      // Same as above, but with the https:// scheme glued onto the bare
      // region: still not a usable OAuth2 origin
      configure({
        cognitoIdpEndpoint: "https://eu-west-1",
        clientId: "test-client-id",
      });
      expect(() => getAuthorizeEndpoint()).toThrow(
        "Cannot determine OAuth2 endpoint"
      );
      expect(() => getTokenEndpoint()).toThrow(
        "Cannot determine OAuth2 endpoint"
      );
    });
  });
});
