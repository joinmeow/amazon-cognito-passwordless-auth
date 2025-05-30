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
export interface TokensFromSignIn {
  accessToken: string;
  idToken: string;
  refreshToken: string;
  expireAt: Date;
  username: string;
  newDeviceMetadata?: {
    deviceKey: string;
    deviceGroupKey: string;
  };
  deviceKey?: string;
  /**
   * Indicates if the user needs to be asked if they want to remember this device.
   * - If true: Your app should ask the user and call updateDeviceStatus API
   * - If false: Device is already remembered based on user pool settings
   */
  userConfirmationNecessary?: boolean;
  /**
   * The authentication method used to obtain these tokens
   * Used for token refresh to determine how to refresh tokens
   */
  authMethod?: "SRP" | "FIDO2" | "PLAINTEXT" | "REDIRECT";
}
export interface TokensFromRefresh {
  accessToken: string;
  /**
   * ID token may be missing in some OAuth flows using custom
   * authorization servers or when the openid scope is not requested
   */
  idToken?: string;
  expireAt: Date;
  username: string;
  deviceKey?: string;
  refreshToken?: string;
  /**
   * The authentication method used to obtain these tokens
   * Used for token refresh to determine how to refresh tokens
   */
  authMethod?: "SRP" | "FIDO2" | "PLAINTEXT" | "REDIRECT";
}

export const busyState = [
  "STARTING_SIGN_IN_WITH_FIDO2",
  "COMPLETING_SIGN_IN_WITH_FIDO2",
  "SIGNING_IN_WITH_PASSWORD",
  "SIGNING_IN_WITH_OTP",
  "SIGNING_OUT",
  "AUTHENTICATING_WITH_DEVICE",
  "STARTING_SIGN_IN_WITH_REDIRECT",
] as const;
export type BusyState = (typeof busyState)[number];
const idleState = [
  "SIGNED_OUT",
  "SIGNED_IN_WITH_FIDO2",
  "SIGNED_IN_WITH_PASSWORD",
  "SIGNED_IN_WITH_SRP_PASSWORD",
  "SIGNED_IN_WITH_PLAINTEXT_PASSWORD",
  "SIGNED_IN_WITH_OTP",
  "FIDO2_SIGNIN_FAILED",
  "SIGNIN_WITH_OTP_FAILED",
  "PASSWORD_SIGNIN_FAILED",
  "SIGNED_IN_WITH_REDIRECT",
  "SIGNIN_WITH_REDIRECT_FAILED",
] as const;
export type IdleState = (typeof idleState)[number];
