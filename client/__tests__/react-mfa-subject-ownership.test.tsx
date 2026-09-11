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
import React from "react";
import {
  act,
  cleanup,
  fireEvent,
  render,
  screen,
} from "@testing-library/react";
import { configure, MinimalFetch, MinimalResponse } from "../config.js";
import { storeTokens, TokensToStore } from "../storage.js";
import {
  PasswordlessContextProvider,
  usePasswordless,
} from "../react/hooks.js";

jest.unmock("../util.js");

const encode = (claims: object) =>
  Buffer.from(JSON.stringify(claims)).toString("base64url");
function tokens(subject: string, revision = 1): TokensToStore {
  const claims = {
    sub: subject,
    username: subject,
    exp: 4_070_908_800,
    iat: 1_767_225_600,
  };
  return {
    username: subject,
    authMethod: "PLAINTEXT",
    expireAt: new Date(claims.exp * 1000),
    accessToken: `e30.${encode({ ...claims, jti: `${subject}-${revision}`, scope: "aws.cognito.signin.user.admin" })}.synthetic`,
    idToken: `e30.${encode({ ...claims, "cognito:username": subject })}.synthetic`,
  };
}

function enabledResponse(): MinimalResponse {
  return {
    ok: true,
    status: 200,
    json: async () => ({
      UserAttributes: [],
      UserMFASettingList: ["SOFTWARE_TOKEN_MFA"],
    }),
  };
}
function failedResponse(): MinimalResponse {
  return {
    ok: true,
    status: 200,
    json: async () => {
      throw new Error("MFA lookup failed");
    },
  };
}
const fetchMfa = jest.fn<ReturnType<MinimalFetch>, Parameters<MinimalFetch>>();

function Probe() {
  const { tokensParsed, mfaStatusReady, totpMfaStatus, refreshTotpMfaStatus } =
    usePasswordless();
  return (
    <>
      <output aria-label="MFA status">{`${tokensParsed?.idToken.sub}:${mfaStatusReady}:${totpMfaStatus.enabled}`}</output>
      <button onClick={() => void refreshTotpMfaStatus()}>Refresh MFA</button>
    </>
  );
}
const status = () => screen.getByLabelText("MFA status").textContent;
async function changeTokens(subject: string, revision = 1) {
  await act(async () => {
    await storeTokens(tokens(subject, revision));
  });
}
async function mountProvider() {
  await changeTokens("first-user");
  await act(async () => {
    render(
      <PasswordlessContextProvider>
        <Probe />
      </PasswordlessContextProvider>
    );
  });
  expect(status()).toBe("first-user:true:true");
}

describe("MFA subject ownership", () => {
  beforeEach(() => {
    jest.useFakeTimers();
    fetchMfa.mockReset().mockImplementation(async () => enabledResponse());
    configure({
      cognitoIdpEndpoint: "https://cognito.test",
      clientId: "test-client",
      storage: localStorage,
      fetch: fetchMfa,
    });
  });
  afterEach(() => {
    cleanup();
    jest.useRealTimers();
  });

  it.each(["automatic", "manual"])(
    "does not inherit another subject's MFA after a failed %s check",
    async (refresh) => {
      await mountProvider();
      fetchMfa.mockImplementation(async () => failedResponse());
      await changeTokens("second-user");
      expect(status()).toBe("second-user:false:false");
      await act(async () => {
        if (refresh === "manual")
          fireEvent.click(screen.getByText("Refresh MFA"));
        else await jest.advanceTimersByTimeAsync(5000);
      });
      expect(status()).toBe("second-user:true:false");
      await changeTokens("second-user", 2);
      expect(status()).toBe("second-user:false:false");
      fetchMfa.mockImplementation(async () => enabledResponse());
      await act(async () => {
        fireEvent.click(screen.getByText("Refresh MFA"));
      });
      expect(status()).toBe("second-user:true:true");
    }
  );

  it("rechecks the original token after switching subjects during cooldown", async () => {
    await mountProvider();
    await changeTokens("second-user");
    await changeTokens("first-user");
    expect(status()).toBe("first-user:false:false");
    await act(async () => {
      await jest.advanceTimersByTimeAsync(5000);
    });
    expect(status()).toBe("first-user:true:true");
    expect(fetchMfa).toHaveBeenCalledTimes(2);
  });

  it("rejects a late manual MFA response from the previous subject", async () => {
    await mountProvider();
    let resolveResponse: (response: MinimalResponse) => void = () => {
      throw new Error("Request not started");
    };
    fetchMfa.mockImplementationOnce(
      () =>
        new Promise((resolve) => {
          resolveResponse = resolve;
        })
    );
    await act(async () => {
      fireEvent.click(screen.getByText("Refresh MFA"));
    });
    expect(fetchMfa).toHaveBeenCalledTimes(2);
    await changeTokens("second-user");
    await act(async () => {
      resolveResponse(enabledResponse());
    });
    expect(status()).toBe("second-user:false:false");
  });

  it("retains confirmed MFA through a failed same-subject refresh", async () => {
    await mountProvider();
    fetchMfa.mockImplementation(async () => failedResponse());
    await changeTokens("first-user", 2);
    expect(status()).toBe("first-user:false:true");
    await act(async () => {
      await jest.advanceTimersByTimeAsync(5000);
    });
    expect(status()).toBe("first-user:true:true");
  });
});
