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
import {
  retrieveDeviceKey,
  clearRememberedDevice,
  getLastAuthUsername,
} from "./storage.js";
import { createDeviceSrpAuthHandler } from "./device.js";
import { parseJwtPayload, redactTokensFromObject } from "./util.js";
import { CognitoAccessTokenPayload } from "./jwt-model.js";

/**
 * Cognito rejects a device key it no longer knows (device forgotten
 * server-side, user pool migrated, ...) with a ResourceNotFoundException
 * whose message mentions the device, e.g. "Device does not exist.".
 * Same detection as amazon-cognito-identity-js uses before it clears its
 * cached device data and retries without the device key.
 */
function isDeviceNotFoundError(err: unknown): err is Error {
  return (
    err instanceof Error &&
    err.name === "ResourceNotFoundException" &&
    err.message.toLowerCase().includes("device")
  );
}

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

      // Look up a remembered device key to send along with initiateAuth, so
      // Cognito can recognize the device and skip MFA where applicable.
      // Confirmed device records are stored under the user's CANONICAL id,
      // while the username entered here may be an alias (e-mail, phone
      // number). The canonical id isn't known until after authentication, so
      // for the common same-browser repeat sign-in we try the record of the
      // user that last signed in here (LastAuthUser holds the canonical id),
      // and fall back to the username as entered (legacy records).
      let actualDeviceKey = deviceKey;
      // The storage key the device key was found under (so we can clear that
      // exact record if Cognito rejects the key as stale)
      let deviceKeyUsername: string | undefined;
      if (!actualDeviceKey) {
        const lastAuthUsername = await getLastAuthUsername();
        for (const candidate of new Set([lastAuthUsername, username])) {
          if (!candidate) continue;
          const storedDeviceKey = await retrieveDeviceKey(candidate);
          if (storedDeviceKey) {
            actualDeviceKey = storedDeviceKey;
            deviceKeyUsername = candidate;
            break;
          }
        }
      }

      const attemptSignIn = async (deviceKeyToUse?: string) => {
        debug?.(`Invoking initiateAuth with username and password ...`);

        const authResponse = await initiateAuth({
          authflow: "USER_PASSWORD_AUTH",
          // initiateAuth adds DEVICE_KEY into the authParameters object it is
          // given, so build a fresh object per attempt
          authParameters: {
            USERNAME: username,
            PASSWORD: password,
          },
          deviceKey: deviceKeyToUse,
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

        // Pre-create a device SRP handler so we can answer DEVICE_SRP_AUTH /
        // DEVICE_PASSWORD_VERIFIER challenges. The device record may be
        // stored under the canonical user id or the username as entered
        // (legacy behavior), so try both — plus the storage key the device
        // key sent with initiateAuth was found under (if any)
        const usernamesToTry = new Set([
          deviceKeyUsername,
          canonicalUserId,
          username,
        ]);
        let deviceHandler:
          | Awaited<ReturnType<typeof createDeviceSrpAuthHandler>>
          | undefined;
        for (const usernameToTry of usernamesToTry) {
          if (!usernameToTry) continue;
          const handlerDeviceKey =
            deviceKeyToUse ?? (await retrieveDeviceKey(usernameToTry));
          if (!handlerDeviceKey) continue;
          deviceHandler = await createDeviceSrpAuthHandler(
            usernameToTry,
            handlerDeviceKey
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

        return { authResponse, tokens };
      };

      let attemptResult: Awaited<ReturnType<typeof attemptSignIn>>;
      try {
        attemptResult = await attemptSignIn(actualDeviceKey);
      } catch (err) {
        if (!actualDeviceKey || !isDeviceNotFoundError(err)) {
          throw err;
        }
        // The device key we sent is stale: Cognito no longer knows the
        // device. Clear the local record it came from and retry ONCE without
        // a device key, so the user can still sign in (with MFA)
        debug?.(
          `Cognito rejected the device key (${err.message}), clearing the stale device record and retrying sign-in without it`
        );
        if (deviceKeyUsername) {
          await clearRememberedDevice(deviceKeyUsername);
        }
        attemptResult = await attemptSignIn(undefined);
      }
      const { authResponse, tokens } = attemptResult;

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
