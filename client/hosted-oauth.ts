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
import { generateRandomString, generatePkcePair } from "./oauthUtil.js";
import { storeTokens } from "./storage.js";

const STATE_KEY = "cognito_oauth_state";
const PKCE_KEY = "cognito_oauth_pkce";
const OAUTH_IN_PROGRESS_KEY = "cognito_oauth_in_progress";

export async function signInWithRedirect({
  provider = "COGNITO",
  customState,
}: { provider?: string; customState?: string } = {}) {
  const cfg = configure();
  if (!cfg.hostedUi) {
    throw new Error("hostedUi configuration missing");
  }
  const {
    domain,
    redirectSignIn,
    scopes,
    responseType = "code",
  } = cfg.hostedUi;
  const stateRandom = generateRandomString(32);
  const state = customState
    ? `${stateRandom}-${btoa(customState)}`
    : stateRandom;

  const { verifier, challenge, method } = await generatePkcePair();

  await cfg.storage.setItem(STATE_KEY, state);
  await cfg.storage.setItem(PKCE_KEY, verifier);
  await cfg.storage.setItem(OAUTH_IN_PROGRESS_KEY, "true");

  const query: Record<string, string> = {
    client_id: cfg.clientId,
    redirect_uri: redirectSignIn,
    response_type: responseType,
    scope: (scopes ?? ["openid", "email", "profile"]).join(" "),
    state,
    identity_provider: provider,
  };
  if (responseType === "code") {
    query.code_challenge = challenge;
    query.code_challenge_method = method;
  }

  const qs = new URLSearchParams(query).toString();
  cfg.location.href = `https://${domain}/oauth2/authorize?${qs}`;
}

export async function handleCognitoOAuthCallback(): Promise<void> {
  const cfg = configure();
  if (!cfg.hostedUi) return;
  const { redirectSignIn, responseType = "code" } = cfg.hostedUi;
  const inFlight = await cfg.storage.getItem(OAUTH_IN_PROGRESS_KEY);
  if (inFlight !== "true") return; // not our redirect

  const url = new URL(cfg.location.href);
  if (
    url.origin + url.pathname !==
    new URL(redirectSignIn).origin + new URL(redirectSignIn).pathname
  ) {
    // Not on the redirect URL
    return;
  }

  const error = url.searchParams.get("error");
  if (error) {
    await clear();
    throw new Error(url.searchParams.get("error_description") ?? error);
  }
  const returnedState = url.searchParams.get("state");
  const storedState = await cfg.storage.getItem(STATE_KEY);
  if (!returnedState || returnedState !== storedState) {
    await clear();
    throw new Error("OAuth state mismatch");
  }

  if (responseType === "code") {
    const code = url.searchParams.get("code");
    if (!code) {
      await clear();
      throw new Error("Authorization code missing");
    }
    await exchangeCodeForTokens(code);
  } else {
    // implicit flow: tokens are in hash
    const hash = url.hash.substring(1);
    const params = new URLSearchParams(hash);
    const access_token = params.get("access_token");
    const id_token = params.get("id_token");
    const expires_in = params.get("expires_in");
    const refresh_token = params.get("refresh_token");
    if (!access_token || !id_token) {
      await clear();
      throw new Error("Tokens missing in implicit flow");
    }
    const expireAt = new Date(Date.now() + Number(expires_in ?? "3600") * 1000);
    await storeTokens({
      accessToken: access_token,
      idToken: id_token,
      refreshToken: refresh_token ?? undefined,
      expireAt,
    });
  }
  // cleanup URL
  cfg.history.pushState(null, "", redirectSignIn);
  await clear();
}

async function exchangeCodeForTokens(code: string) {
  const cfg = configure();
  const { domain, redirectSignIn } = cfg.hostedUi!;
  const verifier = (await cfg.storage.getItem(PKCE_KEY)) ?? "";
  const body = new URLSearchParams({
    grant_type: "authorization_code",
    client_id: cfg.clientId,
    code,
    redirect_uri: redirectSignIn,
    code_verifier: verifier,
  }).toString();
  const tokenEndpoint = `https://${domain}/oauth2/token`;
  const res = await cfg.fetch(tokenEndpoint, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body,
  });
  if (!res.ok) {
    await clear();
    // Attempt to parse error response safely
    type CognitoErrorResponse = {
      error?: string;
      error_description?: string;
    };

    const errJson: unknown = await res.json();

    let message = "Token exchange failed";
    if (
      errJson &&
      typeof errJson === "object" &&
      "error_description" in errJson &&
      typeof (errJson as CognitoErrorResponse).error_description === "string"
    ) {
      message = (errJson as CognitoErrorResponse).error_description as string;
    } else if (
      errJson &&
      typeof errJson === "object" &&
      "error" in errJson &&
      typeof (errJson as CognitoErrorResponse).error === "string"
    ) {
      message = (errJson as CognitoErrorResponse).error as string;
    }

    throw new Error(message);
  }
  const json = (await res.json()) as {
    access_token: string;
    id_token: string;
    refresh_token?: string;
    expires_in: number;
    token_type: string;
  };
  const expireAt = new Date(Date.now() + json.expires_in * 1000);
  await storeTokens({
    accessToken: json.access_token,
    idToken: json.id_token,
    refreshToken: json.refresh_token,
    expireAt,
  });
}

async function clear() {
  const cfg = configure();
  await cfg.storage.removeItem(STATE_KEY);
  await cfg.storage.removeItem(PKCE_KEY);
  await cfg.storage.removeItem(OAUTH_IN_PROGRESS_KEY);
}

// Utility re-exports for other modules
export { generateRandomString } from "./oauthUtil.js";
