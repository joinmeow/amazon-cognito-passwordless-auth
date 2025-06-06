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
import { parseJwtPayload, throwIfNot2xx, bufferToBase64 } from "./util.js";
import { configure, MinimalResponse } from "./config.js";
import { retrieveTokens } from "./storage.js";
import { CognitoSecurityProvider } from "./cognito-security.js";
import { createDeviceSrpAuthHandler, DeviceSrpAuthResult } from "./device.js";

const AWS_REGION_REGEXP = /^[a-z]{2}-[a-z]+-\d$/;

interface ErrorResponse {
  __type: string;
  message: string;
}

// Type alias for better readability below
export type Session = string;

type ChallengeName =
  | "CUSTOM_CHALLENGE"
  | "PASSWORD_VERIFIER"
  | "SMS_MFA"
  | "NEW_PASSWORD_REQUIRED"
  | "SOFTWARE_TOKEN_MFA"
  | "DEVICE_SRP_AUTH"
  | "DEVICE_PASSWORD_VERIFIER";

interface ChallengeResponse {
  ChallengeName: ChallengeName;
  ChallengeParameters: Record<string, string>;
  Session: Session;
}

interface AuthenticatedResponse {
  AuthenticationResult: {
    AccessToken: string;
    IdToken: string;
    RefreshToken: string;
    ExpiresIn: number;
    TokenType: string;
    NewDeviceMetadata?: {
      DeviceKey: string;
      DeviceGroupKey: string;
    };
  };
  ChallengeParameters: Record<string, string>;
}

interface RefreshResponse {
  AuthenticationResult: {
    AccessToken: string;
    IdToken: string;
    /** Optional refresh token from InitiateAuth with REFRESH_TOKEN flow */
    RefreshToken?: string;
    ExpiresIn: number;
    TokenType: string;
  };
  ChallengeParameters: Record<string, string>;
}

interface GetIdResponse {
  IdentityId: string;
}

interface GetCredentialsForIdentityResponse {
  Credentials: {
    AccessKeyId: string;
    Expiration: number;
    SecretKey: string;
    SessionToken: string;
  };
  IdentityId: string;
}

interface GetUserResponse {
  MFAOptions: {
    AttributeName: string;
    DeliveryMedium: string;
  }[];
  PreferredMfaSetting: string;
  UserAttributes: {
    Name: string;
    Value: string;
  }[];
  UserMFASettingList: string[];
  Username: string;
}

interface GetTokensFromRefreshTokenResponse {
  AuthenticationResult: {
    AccessToken: string;
    IdToken: string;
    RefreshToken?: string;
    ExpiresIn: number;
    TokenType: string;
    NewDeviceMetadata?: {
      DeviceKey: string;
      DeviceGroupKey: string;
    };
  };
}

export function isErrorResponse(obj: unknown): obj is ErrorResponse {
  return (
    !!obj && typeof obj === "object" && "__type" in obj && "message" in obj
  );
}

export function assertIsNotErrorResponse<T>(
  obj: T | ErrorResponse
): asserts obj is T {
  if (isErrorResponse(obj)) {
    const err = new Error();
    err.name = obj.__type;
    err.message = obj.message;
    throw err;
  }
}

export function assertIsNotChallengeResponse<T>(
  obj: T | ChallengeResponse
): asserts obj is T {
  if (isChallengeResponse(obj)) {
    throw new Error(`Unexpected challenge: ${obj.ChallengeName}`);
  }
}

export function assertIsNotAuthenticatedResponse<T>(
  obj: T | AuthenticatedResponse
): asserts obj is T {
  if (isAuthenticatedResponse(obj)) {
    throw new Error("Unexpected authentication response");
  }
}

export function isChallengeResponse(obj: unknown): obj is ChallengeResponse {
  return (
    !!obj &&
    typeof obj === "object" &&
    "ChallengeName" in obj &&
    "ChallengeParameters" in obj
  );
}

export function assertIsChallengeResponse(
  obj: unknown
): asserts obj is ChallengeResponse {
  assertIsNotErrorResponse(obj);
  assertIsNotAuthenticatedResponse(obj);
  if (!isChallengeResponse(obj)) {
    throw new Error("Expected challenge response");
  }
}

export function isAuthenticatedResponse(
  obj: unknown
): obj is AuthenticatedResponse {
  return !!obj && typeof obj === "object" && "AuthenticationResult" in obj;
}

export function assertIsAuthenticatedResponse(
  obj: unknown
): asserts obj is AuthenticatedResponse {
  assertIsNotErrorResponse(obj);
  assertIsNotChallengeResponse(obj);
  if (!isAuthenticatedResponse(obj)) {
    throw new Error("Expected authentication response");
  }
}

export function assertIsSignInResponse(
  obj: unknown
): asserts obj is AuthenticatedResponse | ChallengeResponse {
  assertIsNotErrorResponse(obj);
  if (!isAuthenticatedResponse(obj) && !isChallengeResponse(obj)) {
    throw new Error("Expected sign-in response");
  }
}

export async function initiateAuth<
  T extends
    | "CUSTOM_AUTH"
    | "REFRESH_TOKEN"
    | "USER_SRP_AUTH"
    | "USER_PASSWORD_AUTH",
>({
  authflow,
  authParameters,
  clientMetadata,
  deviceKey,
  abort,
}: {
  authflow: T;
  authParameters: Record<string, string>;
  clientMetadata?: Record<string, string>;
  deviceKey?: string;
  abort?: AbortSignal;
}) {
  const {
    fetch,
    cognitoIdpEndpoint,
    proxyApiHeaders,
    clientId,
    clientSecret,
    debug,
  } = configure();

  // Enhance with security context data if it's an authentication flow and a username is provided
  let userContextData;

  if (authflow !== "REFRESH_TOKEN" && authParameters.USERNAME) {
    try {
      // Use our security provider to get encoded data
      const securityProvider = CognitoSecurityProvider.getInstance();
      const encodedData = await securityProvider.getSecurityData(
        authParameters.USERNAME
      );

      if (encodedData) {
        userContextData = {
          EncodedData: encodedData,
        };
        debug?.("User context data successfully collected for initiateAuth");
      }
    } catch (err) {
      // Don't fail auth if context collection fails
      debug?.("Failed to collect user context data for initiateAuth:", err);
    }
  }

  // Add device key to auth parameters if provided and it's a valid authentication flow for device
  if (
    deviceKey &&
    (authflow === "REFRESH_TOKEN" ||
      authflow === "USER_PASSWORD_AUTH" ||
      authflow === "USER_SRP_AUTH" ||
      authflow === "CUSTOM_AUTH")
  ) {
    debug?.(`Including device key ${deviceKey} in ${authflow} flow`);
    authParameters.DEVICE_KEY = deviceKey;
  }

  return fetch(
    cognitoIdpEndpoint.match(AWS_REGION_REGEXP)
      ? `https://cognito-idp.${cognitoIdpEndpoint}.amazonaws.com/`
      : cognitoIdpEndpoint,
    {
      signal: abort,
      headers: {
        "x-amz-target": "AWSCognitoIdentityProviderService.InitiateAuth",
        "content-type": "application/x-amz-json-1.1",
        ...proxyApiHeaders,
      },
      method: "POST",
      body: JSON.stringify({
        AuthFlow: authflow,
        ClientId: clientId,
        AuthParameters: {
          ...authParameters,
          ...(clientSecret && {
            SECRET_HASH: await calculateSecretHash(authParameters.USERNAME),
          }),
        },
        ClientMetadata: clientMetadata,
        ...(userContextData && { UserContextData: userContextData }),
      }),
    }
  ).then(extractInitiateAuthResponse(authflow));
}

export async function respondToAuthChallenge({
  challengeName,
  challengeResponses,
  session,
  clientMetadata,
  abort,
}: {
  challengeName: ChallengeName;
  challengeResponses: Record<string, string>;
  session?: Session;
  clientMetadata?: Record<string, string>;
  abort?: AbortSignal;
}) {
  const {
    fetch,
    cognitoIdpEndpoint,
    proxyApiHeaders,
    clientId,
    clientSecret,
    debug,
  } = configure();

  // Enhance with security context data if a username is provided
  let userContextData;

  if (challengeResponses.USERNAME) {
    try {
      // Use our security provider to get encoded data
      const securityProvider = CognitoSecurityProvider.getInstance();
      const encodedData = await securityProvider.getSecurityData(
        challengeResponses.USERNAME
      );

      if (encodedData) {
        userContextData = {
          EncodedData: encodedData,
        };
        debug?.(
          "User context data successfully collected for respondToAuthChallenge"
        );
      }
    } catch (err) {
      // Don't fail auth if context collection fails
      debug?.(
        "Failed to collect user context data for respondToAuthChallenge:",
        err
      );
    }
  }

  return fetch(
    cognitoIdpEndpoint.match(AWS_REGION_REGEXP)
      ? `https://cognito-idp.${cognitoIdpEndpoint}.amazonaws.com/`
      : cognitoIdpEndpoint,
    {
      headers: {
        "x-amz-target":
          "AWSCognitoIdentityProviderService.RespondToAuthChallenge",
        "content-type": "application/x-amz-json-1.1",
        ...proxyApiHeaders,
      },
      method: "POST",
      body: JSON.stringify({
        ChallengeName: challengeName,
        ChallengeResponses: {
          ...challengeResponses,
          ...(clientSecret && {
            SECRET_HASH: await calculateSecretHash(challengeResponses.USERNAME),
          }),
        },
        ClientId: clientId,
        Session: session,
        ClientMetadata: clientMetadata,
        ...(userContextData && { UserContextData: userContextData }),
      }),
      signal: abort,
    }
  ).then(extractChallengeResponse);
}

/**
 * Confirms the sign-up of a user in Amazon Cognito.
 * Automatically collects and includes threat protection data when available.
 *
 * @param params - The parameters for confirming the sign-up.
 * @param params.username - The username or alias (e-mail, phone number) of the user.
 * @param params.confirmationCode - The confirmation code received by the user.
 * @param [params.clientMetadata] - Additional metadata to be passed to the server.
 * @param [params.forceAliasCreation] - When true, forces user confirmation despite existing aliases.
 * @param [params.abort] - An optional AbortSignal object that can be used to abort the request.
 * @returns A promise that resolves to the response of the confirmation request.
 */
export async function confirmSignUp({
  username,
  confirmationCode,
  clientMetadata,
  forceAliasCreation,
  abort,
}: {
  username: string;
  confirmationCode: string;
  clientMetadata?: Record<string, string>;
  forceAliasCreation?: boolean;
  abort?: AbortSignal;
}) {
  const { fetch, cognitoIdpEndpoint, proxyApiHeaders, clientId, clientSecret } =
    configure();

  // Security-forward approach: attempt to collect user context data by default
  let userContextData;

  try {
    // Use our security provider to get encoded data
    const securityProvider = CognitoSecurityProvider.getInstance();
    const encodedData = await securityProvider.getSecurityData(username);

    if (encodedData) {
      userContextData = {
        EncodedData: encodedData,
      };
    }
  } catch (err) {
    // Don't fail the sign-up if context collection fails
  }

  return fetch(
    cognitoIdpEndpoint.match(AWS_REGION_REGEXP)
      ? `https://cognito-idp.${cognitoIdpEndpoint}.amazonaws.com/`
      : cognitoIdpEndpoint,
    {
      headers: {
        "x-amz-target": "AWSCognitoIdentityProviderService.ConfirmSignUp",
        "content-type": "application/x-amz-json-1.1",
        ...proxyApiHeaders,
      },
      method: "POST",
      body: JSON.stringify({
        Username: username,
        ConfirmationCode: confirmationCode,
        ClientId: clientId,
        ClientMetadata: clientMetadata,
        ...(forceAliasCreation !== undefined && {
          ForceAliasCreation: forceAliasCreation,
        }),
        ...(userContextData && { UserContextData: userContextData }),
        ...(clientSecret && {
          SecretHash: await calculateSecretHash(username),
        }),
      }),
      signal: abort,
    }
  ).then(throwIfNot2xx);
}

export async function revokeToken({
  refreshToken,
  abort,
}: {
  refreshToken: string;
  abort?: AbortSignal;
}) {
  const { fetch, cognitoIdpEndpoint, proxyApiHeaders, clientId } = configure();
  return fetch(
    cognitoIdpEndpoint.match(AWS_REGION_REGEXP)
      ? `https://cognito-idp.${cognitoIdpEndpoint}.amazonaws.com/`
      : cognitoIdpEndpoint,
    {
      headers: {
        "x-amz-target": "AWSCognitoIdentityProviderService.RevokeToken",
        "content-type": "application/x-amz-json-1.1",
        ...proxyApiHeaders,
      },
      method: "POST",
      body: JSON.stringify({
        Token: refreshToken,
        ClientId: clientId,
      }),
      signal: abort,
    }
  ).then(throwIfNot2xx);
}

export async function getTokensFromRefreshToken({
  refreshToken,
  deviceKey,
  clientMetadata,
  abort,
}: {
  refreshToken: string;
  deviceKey?: string;
  clientMetadata?: Record<string, string>;
  abort?: AbortSignal;
}) {
  const {
    fetch,
    cognitoIdpEndpoint,
    proxyApiHeaders,
    clientId,
    clientSecret,
    debug,
  } = configure();

  debug?.(
    "Getting tokens using refresh token with GetTokensFromRefreshToken API"
  );

  // Build the request body
  const requestBody: {
    ClientId: string;
    RefreshToken: string;
    DeviceKey?: string;
    ClientMetadata?: Record<string, string>;
    ClientSecret?: string;
  } = {
    ClientId: clientId,
    RefreshToken: refreshToken,
  };

  // Add optional parameters if provided
  if (deviceKey) {
    debug?.(`Including device key in refresh token request: ${deviceKey}`);
    requestBody.DeviceKey = deviceKey;
  }

  if (clientMetadata) {
    debug?.(
      `Including client metadata in refresh token request: ${JSON.stringify(clientMetadata)}`
    );
    requestBody.ClientMetadata = clientMetadata;
  }

  if (clientSecret) {
    debug?.(
      `Including client secret in refresh token request (length: ${clientSecret.length})`
    );
    requestBody.ClientSecret = clientSecret;
  }

  debug?.(`Requesting tokens from endpoint: ${cognitoIdpEndpoint}`);
  debug?.(
    `Request body structure: ${JSON.stringify({
      hasClientId: !!clientId,
      refreshTokenLength: refreshToken.length,
      hasDeviceKey: !!deviceKey,
      hasClientMetadata: !!clientMetadata,
      hasClientSecret: !!clientSecret,
    })}`
  );

  try {
    const response = await fetch(
      cognitoIdpEndpoint.match(AWS_REGION_REGEXP)
        ? `https://cognito-idp.${cognitoIdpEndpoint}.amazonaws.com/`
        : cognitoIdpEndpoint,
      {
        signal: abort,
        headers: {
          "x-amz-target":
            "AWSCognitoIdentityProviderService.GetTokensFromRefreshToken",
          "content-type": "application/x-amz-json-1.1",
          ...proxyApiHeaders,
        },
        method: "POST",
        body: JSON.stringify(requestBody),
      }
    );

    // Parse response JSON
    const resOk = await throwIfNot2xx(response);
    const json = await resOk.json();

    assertIsNotErrorResponse(json);

    // Ensure we have a valid AuthenticationResult
    if (!json || typeof json !== "object") {
      debug?.(`Invalid response - not an object: ${typeof json}`);
      throw new Error("Invalid response from GetTokensFromRefreshToken");
    }

    if (!("AuthenticationResult" in json)) {
      debug?.(
        `Invalid response - missing AuthenticationResult property. Keys: ${Object.keys(json).join(", ")}`
      );
      throw new Error("Invalid response from GetTokensFromRefreshToken");
    }

    // Explicitly validate and construct a properly typed response
    const authResult = json.AuthenticationResult as {
      AccessToken: string;
      IdToken: string;
      RefreshToken?: string;
      ExpiresIn: number;
      TokenType: string;
      NewDeviceMetadata?: {
        DeviceKey: string;
        DeviceGroupKey: string;
      };
    };

    if (!authResult.AccessToken || typeof authResult.AccessToken !== "string") {
      debug?.(`Invalid response - missing or invalid AccessToken`);
      throw new Error(
        "Invalid response from GetTokensFromRefreshToken: missing AccessToken"
      );
    }

    if (!authResult.IdToken || typeof authResult.IdToken !== "string") {
      debug?.(`Invalid response - missing or invalid IdToken`);
      throw new Error(
        "Invalid response from GetTokensFromRefreshToken: missing IdToken"
      );
    }

    if (!authResult.ExpiresIn || typeof authResult.ExpiresIn !== "number") {
      debug?.(`Invalid response - missing or invalid ExpiresIn`);
      throw new Error(
        "Invalid response from GetTokensFromRefreshToken: missing ExpiresIn"
      );
    }

    if (!authResult.TokenType || typeof authResult.TokenType !== "string") {
      debug?.(`Invalid response - missing or invalid TokenType`);
      throw new Error(
        "Invalid response from GetTokensFromRefreshToken: missing TokenType"
      );
    }

    // Create a properly typed response object
    const typedResponse: GetTokensFromRefreshTokenResponse = {
      AuthenticationResult: {
        AccessToken: authResult.AccessToken,
        IdToken: authResult.IdToken,
        RefreshToken: authResult.RefreshToken,
        ExpiresIn: authResult.ExpiresIn,
        TokenType: authResult.TokenType,
        NewDeviceMetadata: authResult.NewDeviceMetadata,
      },
    };

    debug?.(
      `AuthenticationResult structure: ${JSON.stringify({
        hasAccessToken: !!authResult.AccessToken,
        hasIdToken: !!authResult.IdToken,
        hasRefreshToken: !!authResult.RefreshToken,
        hasExpiresIn: !!authResult.ExpiresIn,
        hasTokenType: !!authResult.TokenType,
        hasNewDeviceMetadata: !!authResult.NewDeviceMetadata,
      })}`
    );

    return typedResponse;
  } catch (error) {
    debug?.(
      `Error in getTokensFromRefreshToken: ${error instanceof Error ? error.message : String(error)}`
    );
    debug?.(
      `Error stack: ${error instanceof Error ? error.stack : "No stack available"}`
    );
    throw error;
  }
}

export async function getId({
  identityPoolId,
  abort,
}: {
  identityPoolId: string;
  abort?: AbortSignal;
}) {
  const { fetch } = configure();
  const identityPoolRegion = identityPoolId.split(":")[0];
  const { idToken } = (await retrieveTokens()) ?? {};
  if (!idToken) {
    throw new Error("Missing ID token");
  }
  const iss = new URL(parseJwtPayload(idToken)["iss"]);
  return fetch(
    `https://cognito-identity.${identityPoolRegion}.amazonaws.com/`,
    {
      signal: abort,
      headers: {
        "x-amz-target": "AWSCognitoIdentityService.GetId",
        "content-type": "application/x-amz-json-1.1",
      },
      method: "POST",
      body: JSON.stringify({
        IdentityPoolId: identityPoolId,
        Logins: {
          [`${iss.hostname}${iss.pathname}`]: idToken,
        },
      }),
    }
  )
    .then(throwIfNot2xx)
    .then((res) => res.json() as Promise<GetIdResponse | ErrorResponse>);
}

/**
 * Retrieves the user attributes from the Cognito Identity Provider.
 *
 * @param abort - An optional `AbortSignal` object that can be used to abort the request.
 * @returns A promise that resolves to an array of user attributes, where each attribute is represented by an object with `Name` and `Value` properties.
 */
export async function getUser({
  abort,
  accessToken,
}: {
  abort?: AbortSignal;
  accessToken?: string;
}) {
  const { fetch, cognitoIdpEndpoint, proxyApiHeaders } = configure();
  const token = accessToken ?? (await retrieveTokens())?.accessToken;
  return await fetch(
    cognitoIdpEndpoint.match(AWS_REGION_REGEXP)
      ? `https://cognito-idp.${cognitoIdpEndpoint}.amazonaws.com/`
      : cognitoIdpEndpoint,
    {
      headers: {
        "x-amz-target": "AWSCognitoIdentityProviderService.GetUser",
        "content-type": "application/x-amz-json-1.1",
        ...proxyApiHeaders,
      },
      method: "POST",
      body: JSON.stringify({
        AccessToken: token,
      }),
      signal: abort,
    }
  )
    .then(throwIfNot2xx)
    .then((res) => res.json() as Promise<GetUserResponse | ErrorResponse>);
}

export async function getCredentialsForIdentity({
  identityId,
  abort,
}: {
  identityId: string;
  abort?: AbortSignal;
}) {
  const { fetch } = configure();
  const identityPoolRegion = identityId.split(":")[0];
  const { idToken } = (await retrieveTokens()) ?? {};
  if (!idToken) {
    throw new Error("Missing ID token");
  }
  const iss = new URL(parseJwtPayload(idToken)["iss"]);
  return fetch(
    `https://cognito-identity.${identityPoolRegion}.amazonaws.com/`,
    {
      signal: abort,
      headers: {
        "x-amz-target": "AWSCognitoIdentityService.GetCredentialsForIdentity",
        "content-type": "application/x-amz-json-1.1",
      },
      method: "POST",
      body: JSON.stringify({
        IdentityId: identityId,
        Logins: {
          [`${iss.hostname}${iss.pathname}`]: idToken,
        },
      }),
    }
  )
    .then(throwIfNot2xx)
    .then(
      (res) =>
        res.json() as Promise<GetCredentialsForIdentityResponse | ErrorResponse>
    );
}

export async function signUp({
  username,
  password,
  userAttributes,
  clientMetadata,
  validationData,
  abort,
}: {
  /**
   * Username, or alias (e-mail, phone number)
   */
  username: string;
  password: string;
  userAttributes?: { name: string; value: string }[];
  clientMetadata?: Record<string, string>;
  validationData?: { name: string; value: string }[];
  abort?: AbortSignal;
}) {
  const {
    fetch,
    cognitoIdpEndpoint,
    proxyApiHeaders,
    clientId,
    clientSecret,
    debug,
  } = configure();

  // Enhance with security context data
  let userContextData;

  try {
    // Use our security provider to get encoded data
    const securityProvider = CognitoSecurityProvider.getInstance();
    const encodedData = await securityProvider.getSecurityData(username);

    if (encodedData) {
      userContextData = {
        EncodedData: encodedData,
      };
      debug?.("User context data successfully collected for signUp");
    }
  } catch (err) {
    // Don't fail sign-up if context collection fails
    debug?.("Failed to collect user context data for signUp:", err);
  }

  return fetch(
    cognitoIdpEndpoint.match(AWS_REGION_REGEXP)
      ? `https://cognito-idp.${cognitoIdpEndpoint}.amazonaws.com/`
      : cognitoIdpEndpoint,
    {
      headers: {
        "x-amz-target": "AWSCognitoIdentityProviderService.SignUp",
        "content-type": "application/x-amz-json-1.1",
        ...proxyApiHeaders,
      },
      method: "POST",
      body: JSON.stringify({
        Username: username,
        Password: password,
        UserAttributes:
          userAttributes &&
          userAttributes.map(({ name, value }) => ({
            Name: name,
            Value: value,
          })),
        ValidationData:
          validationData &&
          validationData.map(({ name, value }) => ({
            Name: name,
            Value: value,
          })),
        ClientMetadata: clientMetadata,
        ClientId: clientId,
        ...(clientSecret && {
          SecretHash: await calculateSecretHash(username),
        }),
        ...(userContextData && { UserContextData: userContextData }),
      }),
      signal: abort,
    }
  ).then(throwIfNot2xx);
}

export async function updateUserAttributes({
  clientMetadata,
  userAttributes,
  abort,
  accessToken,
}: {
  userAttributes: { name: string; value: string }[];
  clientMetadata?: Record<string, string>;
  abort?: AbortSignal;
  accessToken?: string;
}) {
  const { fetch, cognitoIdpEndpoint, proxyApiHeaders } = configure();
  const token = accessToken ?? (await retrieveTokens())?.accessToken;
  await fetch(
    cognitoIdpEndpoint.match(AWS_REGION_REGEXP)
      ? `https://cognito-idp.${cognitoIdpEndpoint}.amazonaws.com/`
      : cognitoIdpEndpoint,
    {
      headers: {
        "x-amz-target":
          "AWSCognitoIdentityProviderService.UpdateUserAttributes",
        "content-type": "application/x-amz-json-1.1",
        ...proxyApiHeaders,
      },
      method: "POST",
      body: JSON.stringify({
        AccessToken: token,
        ClientMetadata: clientMetadata,
        UserAttributes: userAttributes.map(({ name, value }) => ({
          Name: name,
          Value: value,
        })),
      }),
      signal: abort,
    }
  ).then(throwIfNot2xx);
}

export async function getUserAttributeVerificationCode({
  attributeName,
  clientMetadata,
  abort,
  accessToken,
}: {
  attributeName: string;
  clientMetadata?: Record<string, string>;
  abort?: AbortSignal;
  accessToken?: string;
}) {
  const { fetch, cognitoIdpEndpoint, proxyApiHeaders } = configure();
  const token = accessToken ?? (await retrieveTokens())?.accessToken;
  await fetch(
    cognitoIdpEndpoint.match(AWS_REGION_REGEXP)
      ? `https://cognito-idp.${cognitoIdpEndpoint}.amazonaws.com/`
      : cognitoIdpEndpoint,
    {
      headers: {
        "x-amz-target":
          "AWSCognitoIdentityProviderService.GetUserAttributeVerificationCode",
        "content-type": "application/x-amz-json-1.1",
        ...proxyApiHeaders,
      },
      method: "POST",
      body: JSON.stringify({
        AccessToken: token,
        ClientMetadata: clientMetadata,
        AttributeName: attributeName,
      }),
      signal: abort,
    }
  ).then(throwIfNot2xx);
}

export async function verifyUserAttribute({
  attributeName,
  code,
  abort,
  accessToken,
}: {
  attributeName: string;
  code: string;
  abort?: AbortSignal;
  accessToken?: string;
}) {
  const { fetch, cognitoIdpEndpoint, proxyApiHeaders } = configure();
  const token = accessToken ?? (await retrieveTokens())?.accessToken;
  await fetch(
    cognitoIdpEndpoint.match(AWS_REGION_REGEXP)
      ? `https://cognito-idp.${cognitoIdpEndpoint}.amazonaws.com/`
      : cognitoIdpEndpoint,
    {
      headers: {
        "x-amz-target": "AWSCognitoIdentityProviderService.VerifyUserAttribute",
        "content-type": "application/x-amz-json-1.1",
        ...proxyApiHeaders,
      },
      method: "POST",
      body: JSON.stringify({
        AccessToken: token,
        AttributeName: attributeName,
        Code: code,
      }),
      signal: abort,
    }
  ).then(throwIfNot2xx);
}

export async function setUserMFAPreference({
  smsMfaSettings,
  softwareTokenMfaSettings,
  abort,
  accessToken,
}: {
  smsMfaSettings?: { enabled?: boolean; preferred?: boolean };
  softwareTokenMfaSettings?: { enabled?: boolean; preferred?: boolean };
  abort?: AbortSignal;
  accessToken?: string;
}) {
  const { fetch, cognitoIdpEndpoint, proxyApiHeaders } = configure();
  const token = accessToken ?? (await retrieveTokens())?.accessToken;
  await fetch(
    cognitoIdpEndpoint.match(AWS_REGION_REGEXP)
      ? `https://cognito-idp.${cognitoIdpEndpoint}.amazonaws.com/`
      : cognitoIdpEndpoint,
    {
      headers: {
        "x-amz-target":
          "AWSCognitoIdentityProviderService.SetUserMFAPreference",
        "content-type": "application/x-amz-json-1.1",
        ...proxyApiHeaders,
      },
      method: "POST",
      body: JSON.stringify({
        AccessToken: token,
        SMSMfaSettings: smsMfaSettings && {
          Enabled: smsMfaSettings.enabled,
          PreferredMfa: smsMfaSettings.preferred,
        },
        SoftwareTokenMfaSettings: softwareTokenMfaSettings && {
          Enabled: softwareTokenMfaSettings.enabled,
          PreferredMfa: softwareTokenMfaSettings.preferred,
        },
      }),
      signal: abort,
    }
  ).then(throwIfNot2xx);
}

export async function handleAuthResponse({
  authResponse,
  username,
  smsMfaCode,
  otpMfaCode,
  newPassword,
  customChallengeAnswer,
  deviceHandler,
  clientMetadata,
  abort,
}: {
  authResponse: ChallengeResponse | AuthenticatedResponse;
  /**
   * Username (not alias)
   */
  username: string;
  smsMfaCode?: () => Promise<string>;
  otpMfaCode?: () => Promise<string>;
  newPassword?: () => Promise<string>;
  customChallengeAnswer?: () => Promise<string>;
  /**
   * Handler for device authentication challenges (DEVICE_SRP_AUTH and DEVICE_PASSWORD_VERIFIER)
   */
  deviceHandler?: {
    deviceKey: string;
    generateStep1: () => Promise<{ srpAHex: string }>;
    generateStep2: (
      srpB: string,
      secretBlock: string,
      salt?: string
    ) => Promise<DeviceSrpAuthResult>;
  };
  clientMetadata?: Record<string, string>;
  abort?: AbortSignal;
}) {
  const { debug } = configure();

  // IMPORTANT: Log the username being used for challenges
  debug?.(`Using username "${username}" for all auth challenges`);

  let currentDeviceHandler = deviceHandler;

  for (;;) {
    if (isAuthenticatedResponse(authResponse)) {
      let deviceKey: string | undefined = undefined;

      // Extract deviceKey if present in NewDeviceMetadata
      if (authResponse.AuthenticationResult.NewDeviceMetadata?.DeviceKey) {
        deviceKey =
          authResponse.AuthenticationResult.NewDeviceMetadata.DeviceKey;
        debug?.("Device key obtained from authentication result:", deviceKey);
      } else if (currentDeviceHandler?.deviceKey) {
        // If we're using a device key for authentication, keep track of it
        deviceKey = currentDeviceHandler.deviceKey;
        debug?.("Using device key from device handler:", deviceKey);
      }

      return {
        idToken: authResponse.AuthenticationResult.IdToken,
        accessToken: authResponse.AuthenticationResult.AccessToken,
        expireAt: new Date(
          Date.now() + authResponse.AuthenticationResult.ExpiresIn * 1000
        ),
        refreshToken: authResponse.AuthenticationResult.RefreshToken,
        username,
        newDeviceMetadata: authResponse.AuthenticationResult.NewDeviceMetadata
          ? {
              deviceKey:
                authResponse.AuthenticationResult.NewDeviceMetadata.DeviceKey,
              deviceGroupKey:
                authResponse.AuthenticationResult.NewDeviceMetadata
                  .DeviceGroupKey,
            }
          : undefined,
        deviceKey,
      };
    }
    const responseParameters: Record<string, string> = {};
    if (authResponse.ChallengeName === "SMS_MFA") {
      if (!smsMfaCode) throw new Error("Missing MFA Code");
      responseParameters.SMS_MFA_CODE = await smsMfaCode();
    } else if (authResponse.ChallengeName === "NEW_PASSWORD_REQUIRED") {
      if (!newPassword) throw new Error("Missing new password");
      responseParameters.NEW_PASSWORD = await newPassword();
    } else if (authResponse.ChallengeName === "CUSTOM_CHALLENGE") {
      if (!customChallengeAnswer)
        throw new Error("Missing custom challenge answer");
      responseParameters.ANSWER = await customChallengeAnswer();
    } else if (authResponse.ChallengeName === "SOFTWARE_TOKEN_MFA") {
      if (!otpMfaCode) throw new Error("Missing Software MFA Code");
      responseParameters.SOFTWARE_TOKEN_MFA_CODE = await otpMfaCode();

      // Log the MFA challenge response
      debug?.(
        `Responding to SOFTWARE_TOKEN_MFA challenge with USERNAME "${username}"`
      );
    } else if (authResponse.ChallengeName === "DEVICE_SRP_AUTH") {
      const deviceKey = authResponse.ChallengeParameters.DEVICE_KEY;

      debug?.("Handling DEVICE_SRP_AUTH challenge (step 1)");

      // Ensure we have a handler
      if (!currentDeviceHandler) {
        const created = await createDeviceSrpAuthHandler(username, deviceKey);
        if (!created) {
          throw new Error(
            "Failed to create device SRP handler - device password may be missing"
          );
        }
        currentDeviceHandler = created;
      }

      const { srpAHex } = await currentDeviceHandler.generateStep1();

      // Build minimal response params
      responseParameters.DEVICE_KEY = currentDeviceHandler.deviceKey;
      responseParameters.SRP_A = srpAHex;
    } else if (authResponse.ChallengeName === "DEVICE_PASSWORD_VERIFIER") {
      // Get challenge parameters
      const srpB = authResponse.ChallengeParameters.SRP_B;
      const secretBlock = authResponse.ChallengeParameters.SECRET_BLOCK;
      const deviceKey = authResponse.ChallengeParameters.DEVICE_KEY;

      debug?.("Handling DEVICE_PASSWORD_VERIFIER challenge");
      debug?.("DEVICE_PASSWORD_VERIFIER parameters:", {
        ChallengeParameters: authResponse.ChallengeParameters,
      });

      // Ensure we have a handler (might have been established in previous step)
      if (!currentDeviceHandler) {
        const created = await createDeviceSrpAuthHandler(username, deviceKey);
        if (!created) {
          throw new Error(
            "Failed to create device SRP handler - device password may be missing"
          );
        }
        currentDeviceHandler = created;
      }

      const deviceSrpResult = await currentDeviceHandler.generateStep2(
        srpB,
        secretBlock,
        authResponse.ChallengeParameters.SALT
      );
      responseParameters.DEVICE_KEY = currentDeviceHandler.deviceKey;
      responseParameters.PASSWORD_CLAIM_SIGNATURE =
        deviceSrpResult.passwordVerifier;
      responseParameters.PASSWORD_CLAIM_SECRET_BLOCK =
        deviceSrpResult.passwordClaimSecretBlock;
      responseParameters.TIMESTAMP = deviceSrpResult.timestamp;
    } else {
      throw new Error(`Unsupported challenge: ${authResponse.ChallengeName}`);
    }
    debug?.(`Invoking respondToAuthChallenge ...`);
    const nextAuthResult = await respondToAuthChallenge({
      challengeName: authResponse.ChallengeName,
      challengeResponses: {
        USERNAME: username, // Always use the same username (USER_ID_FOR_SRP) from the initial auth
        ...responseParameters,
      },
      clientMetadata,
      session: authResponse.Session,
      abort,
    });
    debug?.(`Response from respondToAuthChallenge:`, nextAuthResult);
    authResponse = nextAuthResult;
  }
}

function extractInitiateAuthResponse<
  T extends
    | "CUSTOM_AUTH"
    | "REFRESH_TOKEN"
    | "USER_SRP_AUTH"
    | "USER_PASSWORD_AUTH",
>(authflow: T) {
  return async (res: MinimalResponse) => {
    await throwIfNot2xx(res);
    const body = await res.json();
    if (authflow === "REFRESH_TOKEN") {
      assertIsAuthenticatedResponse(body);
    } else {
      assertIsSignInResponse(body);
    }
    return body as T extends "REFRESH_TOKEN"
      ? RefreshResponse
      : AuthenticatedResponse | ChallengeResponse;
  };
}

async function extractChallengeResponse(res: MinimalResponse) {
  await throwIfNot2xx(res);
  const body = await res.json();
  assertIsSignInResponse(body);
  return body;
}

async function calculateSecretHash(username?: string) {
  const { crypto, clientId, clientSecret } = configure();
  username ??= (await retrieveTokens())?.username;
  if (!username) {
    throw new Error("Failed to determine username for calculating secret hash");
  }
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(clientSecret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign", "verify"]
  );
  const signature = await crypto.subtle.sign(
    "HMAC",
    key,
    new TextEncoder().encode(`${username}${clientId}`)
  );
  return bufferToBase64(signature);
}

// Type declaration for the Amazon Cognito Advanced Security module
declare global {
  interface Window {
    AmazonCognitoAdvancedSecurityData?: {
      getData: (
        username: string,
        userPoolId: string,
        clientId: string
      ) => string;
    };
  }
}

/**
 * Resends the confirmation code to a user who has signed up but not confirmed their account.
 * Automatically collects and includes threat protection data when available.
 *
 * @param params - The parameters for resending the confirmation code.
 * @param params.username - The username or alias (e-mail, phone number) of the user.
 * @param [params.clientMetadata] - Additional metadata to be passed to the server.
 * @param [params.abort] - An optional AbortSignal object that can be used to abort the request.
 * @returns A promise that resolves to the response containing code delivery details.
 */
export async function resendConfirmationCode({
  username,
  clientMetadata,
  abort,
}: {
  username: string;
  clientMetadata?: Record<string, string>;
  abort?: AbortSignal;
}) {
  const { fetch, cognitoIdpEndpoint, proxyApiHeaders, clientId, clientSecret } =
    configure();

  // Security-forward approach: attempt to collect user context data by default
  let userContextData;

  try {
    // Use our security provider to get encoded data
    const securityProvider = CognitoSecurityProvider.getInstance();
    const encodedData = await securityProvider.getSecurityData(username);

    if (encodedData) {
      userContextData = {
        EncodedData: encodedData,
      };
    }
  } catch (err) {
    // Don't fail if context collection fails
  }

  return fetch(
    cognitoIdpEndpoint.match(AWS_REGION_REGEXP)
      ? `https://cognito-idp.${cognitoIdpEndpoint}.amazonaws.com/`
      : cognitoIdpEndpoint,
    {
      headers: {
        "x-amz-target":
          "AWSCognitoIdentityProviderService.ResendConfirmationCode",
        "content-type": "application/x-amz-json-1.1",
        ...proxyApiHeaders,
      },
      method: "POST",
      body: JSON.stringify({
        Username: username,
        ClientId: clientId,
        ClientMetadata: clientMetadata,
        ...(clientSecret && {
          SecretHash: await calculateSecretHash(username),
        }),
        ...(userContextData && { UserContextData: userContextData }),
      }),
      signal: abort,
    }
  )
    .then(throwIfNot2xx)
    .then((res) => res.json());
}

/**
 * Sends a password-reset confirmation code to the user.
 * Automatically collects and includes threat protection data when available.
 *
 * @param params - The parameters for the forgot password request.
 * @param params.username - The username or alias (e-mail, phone number) of the user.
 * @param [params.clientMetadata] - Additional metadata to be passed to the server.
 * @param [params.abort] - An optional AbortSignal object that can be used to abort the request.
 * @returns A promise that resolves to the response containing code delivery details.
 */
export async function forgotPassword({
  username,
  clientMetadata,
  abort,
}: {
  username: string;
  clientMetadata?: Record<string, string>;
  abort?: AbortSignal;
}) {
  const { fetch, cognitoIdpEndpoint, proxyApiHeaders, clientId, clientSecret } =
    configure();

  // Security-forward approach: attempt to collect user context data by default
  let userContextData;

  try {
    // Use our security provider to get encoded data
    const securityProvider = CognitoSecurityProvider.getInstance();
    const encodedData = await securityProvider.getSecurityData(username);

    if (encodedData) {
      userContextData = {
        EncodedData: encodedData,
      };
    }
  } catch (err) {
    // Don't fail if context collection fails
  }

  return fetch(
    cognitoIdpEndpoint.match(AWS_REGION_REGEXP)
      ? `https://cognito-idp.${cognitoIdpEndpoint}.amazonaws.com/`
      : cognitoIdpEndpoint,
    {
      headers: {
        "x-amz-target": "AWSCognitoIdentityProviderService.ForgotPassword",
        "content-type": "application/x-amz-json-1.1",
        ...proxyApiHeaders,
      },
      method: "POST",
      body: JSON.stringify({
        Username: username,
        ClientId: clientId,
        ClientMetadata: clientMetadata,
        ...(clientSecret && {
          SecretHash: await calculateSecretHash(username),
        }),
        ...(userContextData && { UserContextData: userContextData }),
      }),
      signal: abort,
    }
  )
    .then(throwIfNot2xx)
    .then((res) => res.json());
}

/**
 * Completes the password reset process by validating the confirmation code and setting a new password.
 * Automatically collects and includes threat protection data when available.
 *
 * @param params - The parameters for confirming the forgot password request.
 * @param params.username - The username or alias (e-mail, phone number) of the user.
 * @param params.confirmationCode - The confirmation code sent to the user.
 * @param params.password - The new password for the user.
 * @param [params.clientMetadata] - Additional metadata to be passed to the server.
 * @param [params.abort] - An optional AbortSignal object that can be used to abort the request.
 * @returns A promise that resolves when the password has been successfully reset.
 */
export async function confirmForgotPassword({
  username,
  confirmationCode,
  password,
  clientMetadata,
  abort,
}: {
  username: string;
  confirmationCode: string;
  password: string;
  clientMetadata?: Record<string, string>;
  abort?: AbortSignal;
}) {
  const { fetch, cognitoIdpEndpoint, proxyApiHeaders, clientId, clientSecret } =
    configure();

  // Security-forward approach: attempt to collect user context data by default
  let userContextData;

  try {
    // Use our security provider to get encoded data
    const securityProvider = CognitoSecurityProvider.getInstance();
    const encodedData = await securityProvider.getSecurityData(username);

    if (encodedData) {
      userContextData = {
        EncodedData: encodedData,
      };
    }
  } catch (err) {
    // Don't fail if context collection fails
  }

  return fetch(
    cognitoIdpEndpoint.match(AWS_REGION_REGEXP)
      ? `https://cognito-idp.${cognitoIdpEndpoint}.amazonaws.com/`
      : cognitoIdpEndpoint,
    {
      headers: {
        "x-amz-target":
          "AWSCognitoIdentityProviderService.ConfirmForgotPassword",
        "content-type": "application/x-amz-json-1.1",
        ...proxyApiHeaders,
      },
      method: "POST",
      body: JSON.stringify({
        Username: username,
        ConfirmationCode: confirmationCode,
        Password: password,
        ClientId: clientId,
        ClientMetadata: clientMetadata,
        ...(clientSecret && {
          SecretHash: await calculateSecretHash(username),
        }),
        ...(userContextData && { UserContextData: userContextData }),
      }),
      signal: abort,
    }
  ).then(throwIfNot2xx);
}

/**
 * Changes the password for a signed-in user.
 * Requires a valid access token from the signed-in user.
 *
 * @param params - The parameters for changing the password.
 * @param params.accessToken - A valid access token for the signed-in user.
 * @param params.previousPassword - The user's current password.
 * @param params.proposedPassword - The new password.
 * @param [params.abort] - An optional AbortSignal object that can be used to abort the request.
 * @returns A promise that resolves when the password has been successfully changed.
 */
export async function changePassword({
  accessToken,
  previousPassword,
  proposedPassword,
  abort,
}: {
  accessToken: string;
  previousPassword: string;
  proposedPassword: string;
  abort?: AbortSignal;
}) {
  const { fetch, cognitoIdpEndpoint, proxyApiHeaders } = configure();

  return fetch(
    cognitoIdpEndpoint.match(AWS_REGION_REGEXP)
      ? `https://cognito-idp.${cognitoIdpEndpoint}.amazonaws.com/`
      : cognitoIdpEndpoint,
    {
      headers: {
        "x-amz-target": "AWSCognitoIdentityProviderService.ChangePassword",
        "content-type": "application/x-amz-json-1.1",
        ...proxyApiHeaders,
      },
      method: "POST",
      body: JSON.stringify({
        AccessToken: accessToken,
        PreviousPassword: previousPassword,
        ProposedPassword: proposedPassword,
      }),
      signal: abort,
    }
  ).then(throwIfNot2xx);
}

/**
 * Changes the password for the currently signed-in user, using the stored access token.
 * This is a convenience method that automatically uses the access token from storage.
 *
 * @param params - The parameters for changing the password.
 * @param params.previousPassword - The user's current password.
 * @param params.proposedPassword - The new password.
 * @param [params.abort] - An optional AbortSignal object that can be used to abort the request.
 * @returns A promise that resolves when the password has been successfully changed.
 */
export async function changePasswordForCurrentUser({
  previousPassword,
  proposedPassword,
  abort,
}: {
  previousPassword: string;
  proposedPassword: string;
  abort?: AbortSignal;
}) {
  const tokens = await retrieveTokens();

  if (!tokens?.accessToken) {
    throw new Error(
      "No access token available. User must be signed in to change password."
    );
  }

  return changePassword({
    accessToken: tokens.accessToken,
    previousPassword,
    proposedPassword,
    abort,
  });
}

/**
 * Begins setup of time-based one-time password (TOTP) multi-factor authentication (MFA) for a user.
 * Returns a unique private key that can be used with authenticator apps like Google Authenticator or Authy.
 *
 * @param params - The parameters for associating a software token.
 * @param [params.accessToken] - A valid access token for the signed-in user. Required if session is not provided.
 * @param [params.session] - A session string from a challenge response. Required if accessToken is not provided.
 * @param [params.abort] - An optional AbortSignal object that can be used to abort the request.
 * @returns A promise that resolves to the response containing the secret code and session.
 */
export async function associateSoftwareToken({
  accessToken,
  session,
  abort,
}: {
  accessToken?: string;
  session?: string;
  abort?: AbortSignal;
}) {
  const { fetch, cognitoIdpEndpoint, proxyApiHeaders } = configure();

  if (!accessToken && !session) {
    throw new Error("Either accessToken or session must be provided");
  }

  return fetch(
    cognitoIdpEndpoint.match(AWS_REGION_REGEXP)
      ? `https://cognito-idp.${cognitoIdpEndpoint}.amazonaws.com/`
      : cognitoIdpEndpoint,
    {
      headers: {
        "x-amz-target":
          "AWSCognitoIdentityProviderService.AssociateSoftwareToken",
        "content-type": "application/x-amz-json-1.1",
        ...proxyApiHeaders,
      },
      method: "POST",
      body: JSON.stringify({
        ...(accessToken && { AccessToken: accessToken }),
        ...(session && { Session: session }),
      }),
      signal: abort,
    }
  )
    .then(throwIfNot2xx)
    .then((res) => res.json());
}

/**
 * Verifies the time-based one-time password (TOTP) multi-factor authentication (MFA) setup for a user.
 * This should be called after associateSoftwareToken to complete the MFA setup.
 *
 * @param params - The parameters for verifying a software token.
 * @param params.userCode - The time-based one-time password that the user provides from their authenticator app.
 * @param [params.accessToken] - A valid access token for the signed-in user. Required if session is not provided.
 * @param [params.session] - A session string from associateSoftwareToken or a challenge response. Required if accessToken is not provided.
 * @param [params.friendlyDeviceName] - A friendly name for the device that will be generating TOTP codes.
 * @param [params.abort] - An optional AbortSignal object that can be used to abort the request.
 * @returns A promise that resolves to the response containing the status of the verification.
 */
export async function verifySoftwareToken({
  userCode,
  accessToken,
  session,
  friendlyDeviceName,
  abort,
}: {
  userCode: string;
  accessToken?: string;
  session?: string;
  friendlyDeviceName?: string;
  abort?: AbortSignal;
}) {
  const { fetch, cognitoIdpEndpoint, proxyApiHeaders } = configure();

  if (!accessToken && !session) {
    throw new Error("Either accessToken or session must be provided");
  }

  return fetch(
    cognitoIdpEndpoint.match(AWS_REGION_REGEXP)
      ? `https://cognito-idp.${cognitoIdpEndpoint}.amazonaws.com/`
      : cognitoIdpEndpoint,
    {
      headers: {
        "x-amz-target": "AWSCognitoIdentityProviderService.VerifySoftwareToken",
        "content-type": "application/x-amz-json-1.1",
        ...proxyApiHeaders,
      },
      method: "POST",
      body: JSON.stringify({
        UserCode: userCode,
        ...(accessToken && { AccessToken: accessToken }),
        ...(session && { Session: session }),
        ...(friendlyDeviceName && { FriendlyDeviceName: friendlyDeviceName }),
      }),
      signal: abort,
    }
  )
    .then(throwIfNot2xx)
    .then((res) => res.json());
}

/**
 * Convenience method for beginning TOTP MFA setup for the currently signed-in user.
 * Automatically uses the stored access token.
 *
 * @param [params.abort] - An optional AbortSignal object that can be used to abort the request.
 * @returns A promise that resolves to the response containing the secret code.
 */
export async function associateSoftwareTokenForCurrentUser({
  abort,
}: {
  abort?: AbortSignal;
} = {}) {
  const tokens = await retrieveTokens();

  if (!tokens?.accessToken) {
    throw new Error(
      "No access token available. User must be signed in to set up TOTP MFA."
    );
  }

  return associateSoftwareToken({
    accessToken: tokens.accessToken,
    abort,
  });
}

/**
 * Convenience method for verifying TOTP MFA setup for the currently signed-in user.
 * Automatically uses the stored access token.
 *
 * @param params.userCode - The time-based one-time password that the user provides from their authenticator app.
 * @param [params.friendlyDeviceName] - A friendly name for the device that will be generating TOTP codes.
 * @param [params.abort] - An optional AbortSignal object that can be used to abort the request.
 * @returns A promise that resolves to the response containing the status of the verification.
 */
export async function verifySoftwareTokenForCurrentUser({
  userCode,
  friendlyDeviceName,
  abort,
}: {
  userCode: string;
  friendlyDeviceName?: string;
  abort?: AbortSignal;
}) {
  const tokens = await retrieveTokens();

  if (!tokens?.accessToken) {
    throw new Error(
      "No access token available. User must be signed in to verify TOTP MFA."
    );
  }

  return verifySoftwareToken({
    userCode,
    accessToken: tokens.accessToken,
    friendlyDeviceName,
    abort,
  });
}

/**
 * Confirms a device to be tracked for a user. This allows for "Remember this device" functionality.
 * For remembered devices, MFA challenges can be skipped on subsequent sign-ins.
 *
 * @param params - The parameters for confirming a device.
 * @param params.accessToken - A valid access token for the signed-in user.
 * @param params.deviceKey - The device key returned during authentication.
 * @param params.deviceName - A friendly name for the device.
 * @param params.deviceSecretVerifierConfig - The SRP configuration for the device.
 * @param [params.abort] - An optional AbortSignal object that can be used to abort the request.
 * @returns A promise that resolves to the response indicating if user confirmation is necessary.
 */
export async function confirmDevice({
  accessToken,
  deviceKey,
  deviceName,
  deviceSecretVerifierConfig,
  abort,
}: {
  accessToken: string;
  deviceKey: string;
  deviceName?: string;
  deviceSecretVerifierConfig: {
    passwordVerifier: string;
    salt: string;
  };
  abort?: AbortSignal;
}) {
  const { fetch, cognitoIdpEndpoint, proxyApiHeaders, debug } = configure();

  debug?.("📱 [Confirm Device] Initiating device confirmation API call");
  debug?.("📱 [Confirm Device] Device key:", deviceKey);
  debug?.("📱 [Confirm Device] Device name:", deviceName || "Not provided");

  // Validate device key format before making the API call
  if (!deviceKey.includes("_")) {
    debug?.(
      "❌ [Confirm Device] Invalid device key format (missing underscore):",
      deviceKey
    );
    throw new Error("Invalid device key format: missing region_uuid format");
  }

  const [region, uuid] = deviceKey.split("_");
  if (!region || !uuid) {
    debug?.("❌ [Confirm Device] Device key missing region or UUID part");
    throw new Error("Invalid device key: missing region or UUID part");
  }

  // Check that UUID looks like a valid UUID (basic validation)
  if (
    !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(
      uuid
    )
  ) {
    debug?.(
      "❌ [Confirm Device] Device key contains invalid UUID format:",
      uuid
    );
    throw new Error("Invalid device key: UUID part has invalid format");
  }

  // Log verifier details for debugging
  debug?.(
    "📱 [Confirm Device] Password verifier length:",
    deviceSecretVerifierConfig.passwordVerifier.length
  );
  debug?.(
    "📱 [Confirm Device] Salt length:",
    deviceSecretVerifierConfig.salt.length
  );

  try {
    debug?.(
      "📱 [Confirm Device] Sending API request to ConfirmDevice endpoint"
    );

    const requestBody = {
      AccessToken: accessToken,
      DeviceKey: deviceKey,
      DeviceSecretVerifierConfig: {
        PasswordVerifier: deviceSecretVerifierConfig.passwordVerifier,
        Salt: deviceSecretVerifierConfig.salt,
      },
      ...(deviceName && { DeviceName: deviceName }),
    };

    debug?.(
      "📱 [Confirm Device] Request structure:",
      JSON.stringify({
        hasAccessToken: !!accessToken,
        accessTokenLength: accessToken.length,
        deviceKey,
        hasDeviceName: !!deviceName,
        verifierLength: deviceSecretVerifierConfig.passwordVerifier.length,
        saltLength: deviceSecretVerifierConfig.salt.length,
      })
    );

    const response = await fetch(
      cognitoIdpEndpoint.match(AWS_REGION_REGEXP)
        ? `https://cognito-idp.${cognitoIdpEndpoint}.amazonaws.com/`
        : cognitoIdpEndpoint,
      {
        headers: {
          "x-amz-target": "AWSCognitoIdentityProviderService.ConfirmDevice",
          "content-type": "application/x-amz-json-1.1",
          ...proxyApiHeaders,
        },
        method: "POST",
        body: JSON.stringify(requestBody),
        signal: abort,
      }
    );

    // Parse response JSON
    const resOk = await throwIfNot2xx(response);
    const json = await resOk.json();

    assertIsNotErrorResponse(json);

    debug?.("✅ [Confirm Device] Device confirmation API call successful");
    debug?.("📱 [Confirm Device] Response:", JSON.stringify(json));

    return json as { UserConfirmationNecessary?: boolean };
  } catch (error) {
    debug?.("❌ [Confirm Device] Device confirmation API call failed:", error);

    // Add detailed error message
    const errorMessage = error instanceof Error ? error.message : String(error);
    debug?.("❌ [Confirm Device] Error details:", errorMessage);

    throw error;
  }
}

/**
 * Updates the device status for a user's device.
 * This is typically called after confirmDevice if the user is prompted to remember the device.
 *
 * @param params - The parameters for updating device status.
 * @param params.accessToken - A valid access token for the signed-in user.
 * @param params.deviceKey - The device key returned during authentication.
 * @param params.deviceRememberedStatus - The remembered status of the device (remembered or not_remembered).
 * @param [params.abort] - An optional AbortSignal object that can be used to abort the request.
 * @returns A promise that resolves when the device status has been updated.
 */
export async function updateDeviceStatus({
  accessToken,
  deviceKey,
  deviceRememberedStatus,
  abort,
}: {
  accessToken: string;
  deviceKey: string;
  deviceRememberedStatus: "remembered" | "not_remembered";
  abort?: AbortSignal;
}) {
  const { fetch, cognitoIdpEndpoint, proxyApiHeaders } = configure();

  return fetch(
    cognitoIdpEndpoint.match(AWS_REGION_REGEXP)
      ? `https://cognito-idp.${cognitoIdpEndpoint}.amazonaws.com/`
      : cognitoIdpEndpoint,
    {
      headers: {
        "x-amz-target": "AWSCognitoIdentityProviderService.UpdateDeviceStatus",
        "content-type": "application/x-amz-json-1.1",
        ...proxyApiHeaders,
      },
      method: "POST",
      body: JSON.stringify({
        AccessToken: accessToken,
        DeviceKey: deviceKey,
        DeviceRememberedStatus: deviceRememberedStatus,
      }),
      signal: abort,
    }
  ).then(throwIfNot2xx);
}

/**
 * Lists all devices for the currently authenticated user.
 *
 * @param params - The parameters for listing devices.
 * @param params.accessToken - A valid access token for the signed-in user.
 * @param [params.limit] - The maximum number of devices to list.
 * @param [params.paginationToken] - The pagination token from a previous list operation.
 * @param [params.abort] - An optional AbortSignal object that can be used to abort the request.
 * @returns A promise that resolves to the list of devices.
 */
export async function listDevices({
  accessToken,
  limit,
  paginationToken,
  abort,
}: {
  accessToken: string;
  limit?: number;
  paginationToken?: string;
  abort?: AbortSignal;
}) {
  const { fetch, cognitoIdpEndpoint, proxyApiHeaders } = configure();

  return fetch(
    cognitoIdpEndpoint.match(AWS_REGION_REGEXP)
      ? `https://cognito-idp.${cognitoIdpEndpoint}.amazonaws.com/`
      : cognitoIdpEndpoint,
    {
      headers: {
        "x-amz-target": "AWSCognitoIdentityProviderService.ListDevices",
        "content-type": "application/x-amz-json-1.1",
        ...proxyApiHeaders,
      },
      method: "POST",
      body: JSON.stringify({
        AccessToken: accessToken,
        ...(limit && { Limit: limit }),
        ...(paginationToken && { PaginationToken: paginationToken }),
      }),
      signal: abort,
    }
  )
    .then(throwIfNot2xx)
    .then((res) => res.json());
}

/**
 * Gets the device information for a specific device.
 *
 * @param params - The parameters for getting device information.
 * @param params.accessToken - A valid access token for the signed-in user.
 * @param params.deviceKey - The device key for the device to get information about.
 * @param [params.abort] - An optional AbortSignal object that can be used to abort the request.
 * @returns A promise that resolves to the device information.
 */
export async function getDevice({
  accessToken,
  deviceKey,
  abort,
}: {
  accessToken: string;
  deviceKey: string;
  abort?: AbortSignal;
}) {
  const { fetch, cognitoIdpEndpoint, proxyApiHeaders } = configure();

  return fetch(
    cognitoIdpEndpoint.match(AWS_REGION_REGEXP)
      ? `https://cognito-idp.${cognitoIdpEndpoint}.amazonaws.com/`
      : cognitoIdpEndpoint,
    {
      headers: {
        "x-amz-target": "AWSCognitoIdentityProviderService.GetDevice",
        "content-type": "application/x-amz-json-1.1",
        ...proxyApiHeaders,
      },
      method: "POST",
      body: JSON.stringify({
        AccessToken: accessToken,
        DeviceKey: deviceKey,
      }),
      signal: abort,
    }
  )
    .then(throwIfNot2xx)
    .then((res) => res.json());
}

/**
 * Removes the specified device from the user's account.
 *
 * @param params - The parameters for forgetting a device.
 * @param params.accessToken - A valid access token for the signed-in user.
 * @param params.deviceKey - The device key for the device to forget.
 * @param [params.abort] - An optional AbortSignal object that can be used to abort the request.
 * @returns A promise that resolves when the device has been forgotten.
 */
export async function forgetDevice({
  accessToken,
  deviceKey,
  abort,
}: {
  accessToken: string;
  deviceKey: string;
  abort?: AbortSignal;
}) {
  const { fetch, cognitoIdpEndpoint, proxyApiHeaders } = configure();

  return fetch(
    cognitoIdpEndpoint.match(AWS_REGION_REGEXP)
      ? `https://cognito-idp.${cognitoIdpEndpoint}.amazonaws.com/`
      : cognitoIdpEndpoint,
    {
      headers: {
        "x-amz-target": "AWSCognitoIdentityProviderService.ForgetDevice",
        "content-type": "application/x-amz-json-1.1",
        ...proxyApiHeaders,
      },
      method: "POST",
      body: JSON.stringify({
        AccessToken: accessToken,
        DeviceKey: deviceKey,
      }),
      signal: abort,
    }
  ).then(throwIfNot2xx);
}
