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
import { TokensFromRefresh } from "./model.js";
import {
  retrieveTokens,
  TokensFromStorage,
  isDeviceRemembered,
} from "./storage.js";
import { initiateAuth, getTokensFromRefreshToken } from "./cognito-api.js";
import { setTimeoutWallClock } from "./util.js";
import { processTokens } from "./common.js";

let schedulingRefresh: ReturnType<typeof _scheduleRefresh> | undefined =
  undefined;
export async function scheduleRefresh(
  ...args: Parameters<typeof _scheduleRefresh>
) {
  if (!schedulingRefresh) {
    schedulingRefresh = _scheduleRefresh(...args).finally(
      () => (schedulingRefresh = undefined)
    );
  }
  return schedulingRefresh;
}

type TokensForRefresh = Partial<
  Pick<
    TokensFromStorage,
    "refreshToken" | "expireAt" | "username" | "deviceKey"
  >
>;

let clearScheduledRefresh: ReturnType<typeof setTimeoutWallClock> | undefined =
  undefined;
async function _scheduleRefresh({
  abort,
  tokensCb,
  isRefreshingCb,
}: {
  abort?: AbortSignal;
  tokensCb?: (res: TokensFromRefresh) => void | Promise<void>;
  isRefreshingCb?: (isRefreshing: boolean) => unknown;
}) {
  const { debug } = configure();
  clearScheduledRefresh?.();
  const tokens = await retrieveTokens();
  if (abort?.aborted) return;
  // Refresh 30 seconds before expiry
  // Add some jitter, to spread scheduled refreshes might they be
  // requested multiple times (e.g. in multiple components)
  const refreshIn = Math.max(
    0,
    (tokens?.expireAt ?? new Date()).valueOf() -
      Date.now() -
      30 * 1000 -
      (Math.random() - 0.5) * 30 * 1000
  );
  if (refreshIn >= 1000) {
    debug?.(
      `Scheduling refresh of tokens in ${(refreshIn / 1000).toFixed(1)} seconds`
    );
    clearScheduledRefresh = setTimeoutWallClock(
      () =>
        refreshTokens({
          abort,
          tokensCb: async (refreshedTokens) => {
            // Check if we have a new refresh token (refresh token rotation)
            if (
              refreshedTokens.refreshToken &&
              refreshedTokens.refreshToken !== tokens?.refreshToken
            ) {
              debug?.("Refresh token has been rotated with a new token");
            }

            // Call the original tokensCb if provided
            await tokensCb?.(refreshedTokens);
          },
          isRefreshingCb,
          tokens,
        }).catch((err) => debug?.("Failed to refresh tokens:", err)),
      refreshIn
    );
    abort?.addEventListener("abort", clearScheduledRefresh);
  } else {
    refreshTokens({ abort, tokensCb, isRefreshingCb, tokens }).catch((err) =>
      debug?.("Failed to refresh tokens:", err)
    );
  }
  return clearScheduledRefresh;
}

let refreshingTokens: ReturnType<typeof _refreshTokens> | undefined = undefined;
export async function refreshTokens(
  ...args: Parameters<typeof _refreshTokens>
) {
  if (!refreshingTokens) {
    refreshingTokens = _refreshTokens(...args).finally(
      () => (refreshingTokens = undefined)
    );
  }
  return refreshingTokens;
}

const invalidRefreshTokens = new Set<string>();
async function _refreshTokens({
  abort,
  tokensCb,
  isRefreshingCb,
  tokens,
}: {
  abort?: AbortSignal;
  tokensCb?: (res: TokensFromRefresh) => void | Promise<void>;
  isRefreshingCb?: (isRefreshing: boolean) => unknown;
  tokens?: TokensForRefresh;
}): Promise<TokensFromRefresh> {
  isRefreshingCb?.(true);
  try {
    const { debug, useGetTokensFromRefreshToken } = configure();
    if (!tokens) {
      tokens = await retrieveTokens();
    }
    const { refreshToken, username, deviceKey } = tokens ?? {};
    if (!refreshToken || !username) {
      throw new Error("Cannot refresh without refresh token and username");
    }
    if (invalidRefreshTokens.has(refreshToken)) {
      throw new Error(
        `Will not attempt refresh using token that failed previously: ${refreshToken}`
      );
    }

    debug?.(
      `Refreshing tokens using refresh token (using ${useGetTokensFromRefreshToken ? "GetTokensFromRefreshToken" : "InitiateAuth"})...`
    );

    let tokensFromRefresh: TokensFromRefresh;

    if (useGetTokensFromRefreshToken) {
      // Use the new GetTokensFromRefreshToken API
      const authResult = await getTokensFromRefreshToken({
        refreshToken,
        deviceKey:
          deviceKey && (await isDeviceRemembered(deviceKey))
            ? deviceKey
            : undefined,
        abort,
      }).catch((err) => {
        invalidRefreshTokens.add(refreshToken);
        throw err;
      });

      // Create token response with username
      tokensFromRefresh = {
        accessToken: authResult.AuthenticationResult.AccessToken,
        idToken: authResult.AuthenticationResult.IdToken,
        expireAt: new Date(
          Date.now() + authResult.AuthenticationResult.ExpiresIn * 1000
        ),
        username,
        // Include refreshToken if provided in the response (refresh token rotation)
        ...(authResult.AuthenticationResult.RefreshToken && {
          refreshToken: authResult.AuthenticationResult.RefreshToken,
        }),
        // Preserve the device key
        deviceKey,
      };
    } else {
      // Use the legacy InitiateAuth with REFRESH_TOKEN flow
      const authParameters: Record<string, string> = {
        REFRESH_TOKEN: refreshToken,
      };

      // Add device key to auth parameters if available
      if (deviceKey) {
        const remembered = await isDeviceRemembered(deviceKey);
        if (remembered) {
          debug?.("Including remembered device key in refresh token flow");
          authParameters.DEVICE_KEY = deviceKey;
        } else {
          debug?.(
            "Device key exists but is not remembered, skipping in refresh flow"
          );
        }
      }

      const authResult = await initiateAuth({
        authflow: "REFRESH_TOKEN",
        authParameters,
        deviceKey,
        abort,
      }).catch((err) => {
        invalidRefreshTokens.add(refreshToken);
        throw err;
      });

      // Create token response with username
      tokensFromRefresh = {
        accessToken: authResult.AuthenticationResult.AccessToken,
        idToken: authResult.AuthenticationResult.IdToken,
        expireAt: new Date(
          Date.now() + authResult.AuthenticationResult.ExpiresIn * 1000
        ),
        username,
        // Preserve the device key
        deviceKey,
      };
    }

    // First process tokens to handle storage and device confirmation
    const processedTokens = await processTokens(tokensFromRefresh, abort);

    // Then invoke the callback if provided
    if (tokensCb) {
      await tokensCb(processedTokens as TokensFromRefresh);
    }

    return processedTokens as TokensFromRefresh;
  } finally {
    isRefreshingCb?.(false);
  }
}
