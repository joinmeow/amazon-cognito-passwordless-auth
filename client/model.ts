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
}
export interface TokensFromRefresh {
  accessToken: string;
  idToken: string;
  expireAt: Date;
  username: string;
  deviceKey?: string;
  refreshToken?: string;
}

export const busyState = [
  "STARTING_SIGN_IN_WITH_FIDO2",
  "COMPLETING_SIGN_IN_WITH_FIDO2",
  "SIGNING_IN_WITH_PASSWORD",
  "SIGNING_IN_WITH_OTP",
  "SIGNING_OUT",
  "AUTHENTICATING_WITH_DEVICE",
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
] as const;
export type IdleState = (typeof idleState)[number];
