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
import { IdleState, BusyState, TokensFromSignIn } from "./model.js";
import {
  initiateAuth,
  handleAuthResponse,
  isAuthenticatedResponse,
} from "./cognito-api.js";
import { processTokens } from "./common.js";
import { retrieveDeviceKey } from "./storage.js";
import { createDeviceSrpAuthHandler } from "./device.js";
import { parseJwtPayload, redactTokensFromObject } from "./util.js";
import { CognitoAccessTokenPayload } from "./jwt-model.js";

export function authenticateWithPlaintextPassword({
  username,
  password,
  smsMfaCode,
  otpMfaCode,
  newPassword,
  deviceKey,
  tokensCb,
  statusCb,
  clientMetadata,
}: {
  /**
   * Username, or alias (e-mail, phone number)
   */
  username: string;
  password: string;
  smsMfaCode?: () => Promise<string>;
  otpMfaCode?: () => Promise<string>;
  newPassword?: () => Promise<string>;
  /**
   * Device key for device authentication (if available from previous sessions)
   */
  deviceKey?: string;
  tokensCb?: (tokens: TokensFromSignIn) => void | Promise<void>;
  statusCb?: (status: BusyState | IdleState) => void;
  currentStatus?: BusyState | IdleState;
  clientMetadata?: Record<string, string>;
}) {
  const { userPoolId, debug } = configure();
  if (!userPoolId) {
    throw new Error("UserPoolId must be configured");
  }
  const abort = new AbortController();
  const signedIn = (async () => {
    try {
      statusCb?.("SIGNING_IN_WITH_PASSWORD");

      // We'll add device key later after we have username context
      // Do initial authentication without device parameters
      debug?.(`Invoking initiateAuth with username and password only...`);

      const authParameters: Record<string, string> = {
        USERNAME: username,
        PASSWORD: password,
      };

      const authResponse = await initiateAuth({
        authflow: "USER_PASSWORD_AUTH",
        authParameters,
        clientMetadata,
        abort: abort.signal,
      });
      debug?.(
        `Response from initiateAuth:`,
        redactTokensFromObject(authResponse)
      );

      // Resolve the canonical user id, so device records are keyed
      // consistently with the SRP flow (the username as entered may be an
      // alias, e.g. e-mail or phone number)
      let canonicalUserId: string | undefined;
      if (isAuthenticatedResponse(authResponse)) {
        try {
          canonicalUserId = parseJwtPayload<CognitoAccessTokenPayload>(
            authResponse.AuthenticationResult.AccessToken
          ).username;
        } catch (err) {
          debug?.(`Failed to determine username from access token:`, err);
        }
      } else {
        canonicalUserId = authResponse.ChallengeParameters?.USER_ID_FOR_SRP;
      }

      // Look up the device key under the canonical user id first, falling
      // back to the username as entered (legacy behavior) so device records
      // stored by previous versions keep working
      const usernamesToTry = [...new Set([canonicalUserId, username])].filter(
        (u): u is string => !!u
      );
      let deviceHandler:
        | Awaited<ReturnType<typeof createDeviceSrpAuthHandler>>
        | undefined;
      for (const usernameToTry of usernamesToTry) {
        const actualDeviceKey =
          deviceKey ?? (await retrieveDeviceKey(usernameToTry));
        if (!actualDeviceKey) continue;
        // Pre-create device SRP handler if we have a device key
        deviceHandler = await createDeviceSrpAuthHandler(
          usernameToTry,
          actualDeviceKey
        );
        if (deviceHandler) break;
      }

      const tokens = await handleAuthResponse({
        authResponse,
        username: canonicalUserId ?? username,
        smsMfaCode,
        otpMfaCode,
        newPassword,
        deviceHandler,
        clientMetadata,
        abort: abort.signal,
      });

      // Check for new device metadata in the response
      if (
        isAuthenticatedResponse(authResponse) &&
        authResponse.AuthenticationResult.NewDeviceMetadata
      ) {
        debug?.(
          "Got new device metadata in authentication response. This can be used for device authentication in future requests."
        );
      }

      // Always process tokens first - this handles device confirmation, storage, and refresh scheduling
      const processedTokens = (await processTokens(
        {
          ...tokens,
          authMethod: "PLAINTEXT",
        },
        abort.signal
      )) as TokensFromSignIn;

      // Then call the custom tokensCb if provided (for application-specific needs only)
      if (tokensCb) {
        await tokensCb(processedTokens);
      }

      statusCb?.("SIGNED_IN_WITH_PLAINTEXT_PASSWORD");
      return processedTokens;
    } catch (err) {
      statusCb?.("PASSWORD_SIGNIN_FAILED");
      throw err;
    }
  })();
  return {
    signedIn,
    abort: () => abort.abort(),
  };
}
