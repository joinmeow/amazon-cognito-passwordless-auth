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

import { configure } from "../config.js";

describe("fido2.baseUrl scheme validation", () => {
  it("throws when fido2.baseUrl uses plaintext http://", () => {
    // The user's ID token is sent as a Bearer credential to this URL, so a
    // plaintext http:// base is rejected (mirrors the hostedUi.domain check)
    expect(() =>
      configure({
        cognitoIdpEndpoint: "eu-west-1",
        clientId: "test-client-id",
        fido2: {
          baseUrl: "http://fido2.example.com",
        },
      })
    ).toThrow("fido2.baseUrl must not use plaintext http://");
  });

  it("accepts an https:// fido2.baseUrl", () => {
    const config = configure({
      cognitoIdpEndpoint: "eu-west-1",
      clientId: "test-client-id",
      fido2: {
        baseUrl: "https://fido2.example.com",
      },
    });
    expect(config.fido2?.baseUrl).toBe("https://fido2.example.com");
  });
});
