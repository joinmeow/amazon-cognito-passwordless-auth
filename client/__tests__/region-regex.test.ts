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

import { configure, MinimalFetch, MinimalResponse } from "../config.js";
import { revokeToken } from "../cognito-api.js";

// [region, DNS suffix of the region's partition]
const AWS_REGIONS: [region: string, dnsSuffix: string][] = [
  ["us-east-1", "amazonaws.com"],
  ["eu-central-2", "amazonaws.com"],
  ["ap-southeast-3", "amazonaws.com"],
  ["il-central-1", "amazonaws.com"],
  ["mx-central-1", "amazonaws.com"],
  // Partitioned regions (GovCloud, China, European Sovereign Cloud)
  ["us-gov-west-1", "amazonaws.com"],
  ["us-gov-east-1", "amazonaws.com"],
  ["cn-north-1", "amazonaws.com.cn"],
  ["eusc-de-east-1", "amazonaws.eu"],
];

const HOSTNAMES = [
  "example.com",
  "cognito-idp.us-east-1.amazonaws.com",
  "mydomain.auth.us-east-1.amazoncognito.com",
  "localhost",
];

describe("AWS region detection in cognitoIdpEndpoint", () => {
  describe("configure (client/config.ts)", () => {
    test.each(AWS_REGIONS)(
      "leaves AWS region %s untouched (no https:// prefix)",
      (region) => {
        const config = configure({
          cognitoIdpEndpoint: region,
          clientId: "test-client-id",
        });
        expect(config.cognitoIdpEndpoint).toBe(region);
      }
    );

    test.each(HOSTNAMES)("prefixes hostname %s with https://", (hostname) => {
      const config = configure({
        cognitoIdpEndpoint: hostname,
        clientId: "test-client-id",
      });
      expect(config.cognitoIdpEndpoint).toBe(`https://${hostname}`);
    });

    test.each(["https://example.com", "https://localhost:3000"])(
      "leaves https:// URL with protocol %s untouched",
      (url) => {
        const config = configure({
          cognitoIdpEndpoint: url,
          clientId: "test-client-id",
        });
        expect(config.cognitoIdpEndpoint).toBe(url);
      }
    );

    // Passwords, SRP parameters and tokens are POSTed to cognitoIdpEndpoint,
    // so a plaintext http:// endpoint is rejected outright at configure() time.
    test.each(["http://example.com", "http://localhost:3000"])(
      "rejects plaintext http:// URL %s",
      (url) => {
        expect(() =>
          configure({
            cognitoIdpEndpoint: url,
            clientId: "test-client-id",
          })
        ).toThrow("cognitoIdpEndpoint must not use plaintext http://");
      }
    );
  });

  describe("cognito-api endpoint construction (client/cognito-api.ts)", () => {
    const mockFetch = jest.fn<
      ReturnType<MinimalFetch>,
      Parameters<MinimalFetch>
    >();

    beforeEach(() => {
      mockFetch.mockReset();
      mockFetch.mockResolvedValue({
        ok: true,
        status: 200,
        json: () => Promise.resolve({}),
      } as MinimalResponse);
    });

    test.each(AWS_REGIONS)(
      "builds cognito-idp endpoint URL for AWS region %s with DNS suffix %s",
      async (region, dnsSuffix) => {
        configure({
          cognitoIdpEndpoint: region,
          clientId: "test-client-id",
          fetch: mockFetch,
        });
        await revokeToken({ refreshToken: "test-refresh-token" });
        expect(mockFetch).toHaveBeenCalledWith(
          `https://cognito-idp.${region}.${dnsSuffix}/`,
          expect.anything()
        );
      }
    );

    test.each(HOSTNAMES)(
      "uses custom endpoint as-is for hostname %s",
      async (hostname) => {
        configure({
          cognitoIdpEndpoint: hostname,
          clientId: "test-client-id",
          fetch: mockFetch,
        });
        await revokeToken({ refreshToken: "test-refresh-token" });
        expect(mockFetch).toHaveBeenCalledWith(
          `https://${hostname}`,
          expect.anything()
        );
      }
    );
  });
});
