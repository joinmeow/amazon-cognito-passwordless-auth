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

describe("hostedUi implicit flow deprecation warning", () => {
  let warnSpy: jest.SpyInstance;

  beforeEach(() => {
    warnSpy = jest.spyOn(console, "warn").mockImplementation(() => undefined);
  });

  afterEach(() => {
    warnSpy.mockRestore();
  });

  it("does not warn for the default authorization-code flow", () => {
    configure({
      clientId: "test-client-id",
      cognitoIdpEndpoint: "eu-west-1",
      hostedUi: {
        domain: "test.auth.eu-west-1.amazoncognito.com",
        redirectSignIn: "https://app.example.com/signin-redirect",
        responseType: "code",
      },
    });

    expect(warnSpy).not.toHaveBeenCalled();
  });

  it("warns once when the deprecated implicit flow is configured", () => {
    configure({
      clientId: "test-client-id",
      cognitoIdpEndpoint: "eu-west-1",
      hostedUi: {
        domain: "test.auth.eu-west-1.amazoncognito.com",
        redirectSignIn: "https://app.example.com/signin-redirect",
        responseType: "token",
      },
    });

    expect(warnSpy).toHaveBeenCalledTimes(1);
    expect(warnSpy).toHaveBeenCalledWith(
      expect.stringContaining("implicit flow")
    );
    expect(warnSpy).toHaveBeenCalledWith(expect.stringContaining("PKCE"));

    // Reconfiguring with the implicit flow again must not warn a second time
    configure({
      clientId: "test-client-id",
      cognitoIdpEndpoint: "eu-west-1",
      hostedUi: {
        domain: "test.auth.eu-west-1.amazoncognito.com",
        redirectSignIn: "https://app.example.com/signin-redirect",
        responseType: "token",
      },
    });

    expect(warnSpy).toHaveBeenCalledTimes(1);
  });
});
