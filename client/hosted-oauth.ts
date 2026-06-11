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
import { configure, getAuthorizeEndpoint, getTokenEndpoint } from "./config.js";
import { generateRandomString, generatePkcePair } from "./oauthUtil.js";
import {
  parseJwtPayload,
  bufferFromBase64Url,
  bufferToBase64Url,
  redactSecret,
  redactTokensFromObject,
} from "./util.js";
import { CognitoAccessTokenPayload } from "./jwt-model.js";
import { withStorageLock, LockTimeoutError } from "./lock.js";
import { processTokens } from "./common.js";
import { TokensFromSignIn } from "./model.js";

const STATE_KEY = "cognito_oauth_state";
const PKCE_KEY = "cognito_oauth_pkce";
const OAUTH_IN_PROGRESS_KEY = "cognito_oauth_in_progress";

export async function signInWithRedirect({
  provider = "COGNITO",
  customState,
  oauthParams,
}: {
  provider?: string;
  customState?: string;
  oauthParams?: Record<string, string>;
} = {}) {
  const cfg = configure();
  const { debug } = cfg;

  if (!cfg.hostedUi) {
    throw new Error("hostedUi configuration missing");
  }

  const { redirectSignIn, scopes, responseType = "code" } = cfg.hostedUi;

  // Get the OAuth authorize endpoint
  const authorizeEndpoint = getAuthorizeEndpoint();
  debug?.(`Using OAuth authorize endpoint: ${authorizeEndpoint}`);

  // Construct full URL from relative URL if needed
  let fullRedirectUrl = redirectSignIn;

  // Check if the redirectSignIn is relative (doesn't start with http:// or https://)
  if (redirectSignIn && !redirectSignIn.match(/^https?:\/\//)) {
    debug?.(
      `Converting relative redirectSignIn "${redirectSignIn}" to absolute URL`
    );

    // Create a URL object using the current location as base
    const currentUrl = new URL(cfg.location.href);

    // Create a new URL with the current as base and the redirect path as the path
    const absoluteUrl = new URL(redirectSignIn, currentUrl.origin);
    fullRedirectUrl = absoluteUrl.href;

    debug?.(`Converted to absolute URL: ${fullRedirectUrl}`);
  }

  const stateRandom = generateRandomString(32);
  // Encode customState as base64url of its UTF-8 bytes: btoa throws on
  // non-Latin1 characters and emits "+", "/" and "=" which aren't URL-safe
  const state = customState
    ? `${stateRandom}-${bufferToBase64Url(new TextEncoder().encode(customState))}`
    : stateRandom;

  const { verifier, challenge, method } = await generatePkcePair();

  // Wrap OAuth state storage in a lock to prevent race conditions
  const oauthLockKey = `Passwordless.${cfg.clientId}.oauthLock`;

  debug?.("🔒 [OAuth] Acquiring lock for OAuth state storage");

  try {
    await withStorageLock(oauthLockKey, async () => {
      await cfg.storage.setItem(STATE_KEY, state);
      await cfg.storage.setItem(PKCE_KEY, verifier);
      await cfg.storage.setItem(OAUTH_IN_PROGRESS_KEY, "true");
    });
  } catch (error) {
    if (error instanceof LockTimeoutError) {
      debug?.("⏱️ [OAuth] Lock timeout - another OAuth operation in progress");
      throw new Error(
        "Another OAuth operation is in progress. Please try again."
      );
    }
    throw error;
  }

  debug?.("✅ [OAuth] OAuth state stored successfully");

  const query: Record<string, string> = {
    client_id: cfg.clientId,
    redirect_uri: fullRedirectUrl,
    response_type: responseType,
    scope: (scopes ?? ["openid", "email", "profile"]).join(" "),
    state,
    identity_provider: provider,
    ...oauthParams,
  };
  if (responseType === "code") {
    query.code_challenge = challenge;
    query.code_challenge_method = method;
  }

  debug?.(
    `Initiating OAuth redirect with params: ${JSON.stringify({
      ...query,
      state: redactSecret(state),
      ...(query.code_challenge && {
        code_challenge: redactSecret(query.code_challenge),
      }),
    })}`
  );
  const qs = new URLSearchParams(query).toString();

  const oauthUrl = `${authorizeEndpoint}?${qs}`;
  debug?.(`Redirecting to: ${oauthUrl}`);
  cfg.location.href = oauthUrl;
}

export async function handleCognitoOAuthCallback(): Promise<TokensFromSignIn | null> {
  const cfg = configure();
  const { debug } = cfg;

  debug?.("OAuth callback triggered - beginning callback processing");

  if (!cfg.hostedUi) {
    debug?.("No hostedUi config found, ignoring redirect");
    return null;
  }

  const { redirectSignIn, responseType = "code" } = cfg.hostedUi;
  debug?.(
    `OAuth configuration: redirectSignIn=${redirectSignIn}, responseType=${responseType}`
  );

  // Convert relative redirectSignIn to absolute URL if needed
  let fullRedirectUrl = redirectSignIn;
  if (redirectSignIn && !redirectSignIn.match(/^https?:\/\//)) {
    debug?.(
      `Converting relative redirectSignIn "${redirectSignIn}" to absolute URL for comparison`
    );

    // Create a URL object using the current location as base
    const currentUrl = new URL(cfg.location.href);

    // Create a new URL with the current as base and the redirect path as the path
    const absoluteUrl = new URL(redirectSignIn, currentUrl.origin);
    fullRedirectUrl = absoluteUrl.href;

    debug?.(`Converted to absolute URL: ${fullRedirectUrl}`);
  }

  const inFlight = await cfg.storage.getItem(OAUTH_IN_PROGRESS_KEY);
  debug?.(`OAuth in-flight status: ${inFlight}`);

  if (inFlight !== "true") {
    debug?.("No OAuth flow in progress, ignoring redirect");
    return null; // not our redirect
  }

  const url = new URL(cfg.location.href);
  debug?.(`Current URL: ${url.toString()}`);
  debug?.(
    `URL query parameters: ${JSON.stringify(Object.fromEntries(url.searchParams))}`
  );

  const normalize = (u: string) => {
    const { origin, pathname } = new URL(u);
    // Remove trailing slash for reliable comparison
    const path =
      pathname.endsWith("/") && pathname !== "/"
        ? pathname.slice(0, -1)
        : pathname;
    return origin + path;
  };

  const normalizedCurrentUrl = normalize(cfg.location.href);
  const normalizedRedirectUrl = normalize(fullRedirectUrl);
  debug?.(
    `Normalized URLs - Current: ${normalizedCurrentUrl}, Expected: ${normalizedRedirectUrl}`
  );

  if (normalizedCurrentUrl !== normalizedRedirectUrl) {
    debug?.(`URL mismatch, not our expected redirect URL. Ignoring.`);
    return null;
  }

  debug?.("URL matches expected redirect URL, continuing OAuth flow");

  // Mark as processing to prevent duplicate handling in concurrent invocations.
  // This must happen only AFTER the redirect-URL check above: invocations on
  // other URLs must leave the in-progress flag untouched, so the real callback
  // can still be processed when it arrives.
  await cfg.storage.setItem(OAUTH_IN_PROGRESS_KEY, "processing");

  // Per RFC 6749, response parameters (state, error, error_description) are
  // delivered in the query string for the code flow (§4.1.2.1) but in the
  // URL FRAGMENT for the implicit flow (§4.2.2.1). Note: errors are only
  // surfaced AFTER state validation below (RFC 6749 §10.12).
  const hashParams = new URLSearchParams(url.hash.substring(1));

  // For code flow, state is in search params. For implicit flow, it's in hash
  let returnedState = url.searchParams.get("state");
  if (!returnedState && responseType === "token") {
    // Check hash for implicit flow
    returnedState = hashParams.get("state");
  }
  debug?.(`Returned state parameter: ${returnedState?.substring(0, 10)}...`);

  // Wrap OAuth state validation in a lock. State MUST be validated before
  // anything else from the response (notably error/error_description) is
  // acted upon, so that a crafted redirect to the sign-in URI can't surface
  // attacker-chosen text (RFC 6749 §10.12).
  const oauthLockKey = `Passwordless.${cfg.clientId}.oauthLock`;

  try {
    await withStorageLock(oauthLockKey, async () => {
      const storedState = await cfg.storage.getItem(STATE_KEY);
      debug?.(`Stored state from browser: ${storedState?.substring(0, 10)}...`);

      if (!returnedState || returnedState !== storedState) {
        debug?.(
          "OAuth state mismatch - possible CSRF attack or invalidated session"
        );
        await clearInternal();
        throw new Error("OAuth state mismatch");
      }
    });
  } catch (error) {
    // Scrub OAuth params from the URL on every failure exit — including lock
    // timeouts — so code/state/tokens don't linger in the address bar or
    // session history
    cleanupCallbackUrl();
    if (error instanceof LockTimeoutError) {
      debug?.("⏱️ [OAuth] Lock timeout during state validation");
      throw new Error("OAuth operation in progress. Please try again.");
    }
    throw error;
  }

  debug?.("OAuth state validation successful");

  // State is validated, so error/error_description genuinely originate from
  // the OAuth provider's response to OUR request - safe to surface them now.
  // Per RFC 6749 the code flow delivers errors in the query (§4.1.2.1) and
  // only the implicit flow uses the fragment (§4.2.2.1), so the fragment is
  // consulted only for responseType "token" — a crafted #error fragment must
  // not abort a legitimate code-flow callback that carries a valid code
  const oauthError =
    url.searchParams.get("error") ??
    (responseType === "token" ? hashParams.get("error") : null);
  if (oauthError) {
    const errorDesc =
      url.searchParams.get("error_description") ??
      (responseType === "token"
        ? hashParams.get("error_description")
        : null) ??
      oauthError;
    debug?.(`OAuth error received: ${oauthError}, description: ${errorDesc}`);
    // Scrub OAuth params from the URL on this failure exit too
    cleanupCallbackUrl();
    await clear();
    throw new Error(errorDesc);
  }

  // The state is a random hex string, optionally followed by
  // `-<base64url(customState)>` (see signInWithRedirect). The random part is
  // hex only, so the first "-" (if any) marks the start of the customState
  let customState: string | undefined;
  const customStateMatch = returnedState?.match(/^[0-9a-f]+-([A-Za-z0-9_-]+)$/);
  if (customStateMatch) {
    try {
      customState = new TextDecoder().decode(
        bufferFromBase64Url(customStateMatch[1])
      );
      debug?.("Recovered customState from OAuth state parameter");
    } catch (err) {
      debug?.("Failed to decode customState from OAuth state:", err);
    }
  }

  let tokens: TokensFromSignIn;

  if (responseType === "code") {
    const code = url.searchParams.get("code");
    debug?.(`Authorization code received: ${code?.substring(0, 5)}...`);

    if (!code) {
      debug?.("No authorization code in response");
      cleanupCallbackUrl();
      await clear();
      throw new Error("Authorization code missing");
    }

    debug?.("Proceeding to exchange code for tokens");
    try {
      tokens = await exchangeCodeForTokens(code);
    } catch (err) {
      // Scrub the (possibly still valid) authorization code from the URL so
      // it can't be replayed from the address bar or browser history
      cleanupCallbackUrl();
      throw err;
    }
  } else {
    // implicit flow: tokens are in hash
    debug?.("Using implicit flow, extracting tokens from URL hash");
    const hash = url.hash.substring(1);
    const params = new URLSearchParams(hash);
    debug?.(
      `Hash parameters: ${JSON.stringify(
        redactTokensFromObject(Object.fromEntries(params))
      )}`
    );

    const access_token = params.get("access_token");
    const id_token = params.get("id_token");
    const expires_in = params.get("expires_in");
    const refresh_token = params.get("refresh_token");

    debug?.(
      `Tokens extracted - Access token: ${access_token ? "present" : "missing"}, ID token: ${id_token ? "present" : "missing"}, Refresh token: ${refresh_token ? "present" : "missing"}`
    );

    if (!access_token) {
      debug?.("Required access token missing in implicit flow response");
      cleanupCallbackUrl();
      await clear();
      throw new Error("Access token missing in implicit flow");
    }

    // Derive expiry from the access-token's exp claim (server time) to avoid
    // issues with client-clock skew. Fall back to the expires_in field only if
    // parsing fails.
    let expireAt: Date;
    try {
      const { exp } = parseJwtPayload<CognitoAccessTokenPayload>(access_token);
      expireAt = new Date(exp * 1000);
    } catch {
      expireAt = new Date(Date.now() + Number(expires_in ?? "3600") * 1000);
    }
    debug?.(`Token expiry set to: ${expireAt.toISOString()}`);

    // Extract username from access token
    let username: string;
    try {
      const payload = parseJwtPayload<CognitoAccessTokenPayload>(access_token);
      username = payload.username;
    } catch (error) {
      debug?.("Failed to extract username from access token:", error);
      cleanupCallbackUrl();
      throw new Error("Invalid access token received from OAuth");
    }

    // Prepare tokens for processTokens
    const tokensForProcessing: TokensFromSignIn = {
      accessToken: access_token,
      idToken: id_token || "", // Empty string if missing - will be handled by processTokens
      refreshToken: refresh_token || "",
      expireAt,
      username,
      authMethod: "REDIRECT",
      // OAuth doesn't provide device metadata
      newDeviceMetadata: undefined,
      userConfirmationNecessary: false,
    };

    debug?.("Processing OAuth tokens through standard flow (implicit)");

    // Process tokens through the standard flow
    try {
      tokens = (await processTokens(tokensForProcessing)) as TokensFromSignIn;
    } catch (err) {
      // Scrub the tokens from the URL hash so they can't be re-read from the
      // address bar or session history
      cleanupCallbackUrl();
      throw err;
    }

    debug?.("OAuth tokens successfully processed (implicit flow)");
  }

  // cleanup URL
  debug?.("Cleaning up URL, scrubbing OAuth parameters");
  cleanupCallbackUrl();

  await clear();
  debug?.("OAuth flow completed successfully");

  if (customState !== undefined) {
    tokens = { ...tokens, customState };
  }

  return tokens;
}

/**
 * Scrub OAuth parameters (authorization code, state, tokens) from the current
 * URL via history.replaceState, so they are not left in the address bar or
 * browser history (where e.g. an unconsumed authorization code could be
 * replayed). Unrelated query parameters and hash content are preserved.
 */
function cleanupCallbackUrl() {
  const cfg = configure();
  const { debug } = cfg;

  try {
    const url = new URL(cfg.location.href);
    let modified = false;

    // OAuth params delivered in the query string (code flow)
    for (const param of ["code", "state", "error", "error_description"]) {
      if (url.searchParams.has(param)) {
        url.searchParams.delete(param);
        modified = true;
      }
    }

    // OAuth params delivered in the fragment (implicit flow)
    if (url.hash) {
      const hashParams = new URLSearchParams(url.hash.substring(1));
      let hashModified = false;
      for (const param of [
        "access_token",
        "id_token",
        "refresh_token",
        "token_type",
        "expires_in",
        "state",
        "error",
        "error_description",
      ]) {
        if (hashParams.has(param)) {
          hashParams.delete(param);
          hashModified = true;
        }
      }
      if (hashModified) {
        const remaining = hashParams.toString();
        url.hash = remaining ? `#${remaining}` : "";
        modified = true;
      }
    }

    if (!modified) return;

    debug?.(`Scrubbing OAuth parameters from URL, replacing with: ${url.href}`);
    // Use replaceState (not pushState) so the URL carrying the authorization
    // code or tokens doesn't remain reachable one step back in session history
    if (cfg.history.replaceState) {
      cfg.history.replaceState(null, "", url.href);
    } else {
      cfg.history.pushState(null, "", url.href);
    }
  } catch (err) {
    // URL cleanup is best-effort and must never mask the original error
    debug?.("Failed to scrub OAuth parameters from URL:", err);
  }
}

async function exchangeCodeForTokens(code: string): Promise<TokensFromSignIn> {
  const cfg = configure();
  const { debug } = cfg;

  debug?.("Beginning code-to-token exchange");
  const { redirectSignIn } = cfg.hostedUi!;

  // Get the OAuth token endpoint
  const tokenEndpoint = getTokenEndpoint();
  debug?.(`Using OAuth token endpoint: ${tokenEndpoint}`);

  // Handle relative redirectSignIn for the token exchange
  let fullRedirectUrl = redirectSignIn;
  if (redirectSignIn && !redirectSignIn.match(/^https?:\/\//)) {
    debug?.(
      `Converting relative redirectSignIn "${redirectSignIn}" to absolute URL for token exchange`
    );

    // Create a URL object using the current location as base
    const currentUrl = new URL(cfg.location.href);

    // Create a new URL with the current as base and the redirect path as the path
    const absoluteUrl = new URL(redirectSignIn, currentUrl.origin);
    fullRedirectUrl = absoluteUrl.href;

    debug?.(`Using absolute URL for token exchange: ${fullRedirectUrl}`);
  }

  // Wrap PKCE retrieval in a lock to ensure consistency
  const oauthLockKey = `Passwordless.${cfg.clientId}.oauthLock`;
  let verifier = "";

  try {
    await withStorageLock(oauthLockKey, async () => {
      verifier = (await cfg.storage.getItem(PKCE_KEY)) ?? "";
      debug?.(`PKCE verifier retrieved: ${verifier ? "present" : "missing"}`);
    });
  } catch (error) {
    if (error instanceof LockTimeoutError) {
      debug?.("⏱️ [OAuth] Lock timeout during PKCE retrieval");
      throw new Error("OAuth operation in progress. Please try again.");
    }
    throw error;
  }

  const body = new URLSearchParams({
    grant_type: "authorization_code",
    client_id: cfg.clientId,
    code,
    redirect_uri: fullRedirectUrl,
    code_verifier: verifier,
  }).toString();

  debug?.(`Token endpoint: ${tokenEndpoint}`);
  debug?.("Sending token exchange request");

  let res: Awaited<ReturnType<typeof cfg.fetch>>;
  try {
    res = await cfg.fetch(tokenEndpoint, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body,
    });
  } catch (err) {
    debug?.("Token exchange network error:", err);
    await clear();
    throw new Error(
      err instanceof Error ? err.message : "Network error during token exchange"
    );
  }

  debug?.(`Token exchange response success: ${res.ok ? "yes" : "no"}`);

  if (!res.ok) {
    debug?.("Token exchange failed");
    await clear();
    // Attempt to parse error response safely
    type CognitoErrorResponse = {
      error?: string;
      error_description?: string;
    };

    const errJson: unknown = await res.json();
    debug?.(`Error response: ${JSON.stringify(errJson)}`);

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

    debug?.(`Throwing error: ${message}`);
    throw new Error(message);
  }

  debug?.("Token exchange successful, parsing response");
  const json = (await res.json()) as {
    access_token: string;
    id_token: string;
    refresh_token?: string;
    expires_in: number;
    token_type: string;
  };

  debug?.(
    `Tokens received - Access token: ${json.access_token ? "present" : "missing"}, ID token: ${json.id_token ? "present" : "missing"}, Refresh token: ${json.refresh_token ? "present" : "missing"}, Expires in: ${json.expires_in}s`
  );

  // Derive expiry from the access-token's exp claim (server time) to avoid
  // issues with client-clock skew. Fall back to the expires_in field only if
  // parsing fails.
  let expireAt: Date;
  try {
    const { exp } = parseJwtPayload<CognitoAccessTokenPayload>(
      json.access_token
    );
    expireAt = new Date(exp * 1000);
  } catch {
    expireAt = new Date(Date.now() + json.expires_in * 1000);
  }
  debug?.(`Token expiry set to: ${expireAt.toISOString()}`);

  // Extract username from access token
  let username: string;
  try {
    const payload = parseJwtPayload<CognitoAccessTokenPayload>(
      json.access_token
    );
    username = payload.username;
  } catch (error) {
    debug?.("Failed to extract username from access token:", error);
    throw new Error("Invalid access token received from OAuth");
  }

  // Validate we have required tokens
  if (!json.id_token) {
    debug?.("Warning: No ID token in OAuth response");
    // For OAuth flows without ID token, we'll create a minimal one later
  }

  // Prepare tokens for processTokens
  const tokensForProcessing: TokensFromSignIn = {
    accessToken: json.access_token,
    idToken: json.id_token || "", // Empty string if missing - will be handled by processTokens
    refreshToken: json.refresh_token || "",
    expireAt,
    username,
    authMethod: "REDIRECT",
    // OAuth doesn't provide device metadata
    newDeviceMetadata: undefined,
    userConfirmationNecessary: false,
  };

  debug?.("Processing OAuth tokens through standard flow");

  // Process tokens through the standard flow
  // This will handle storage, refresh scheduling, and any callbacks
  const processedTokens = await processTokens(tokensForProcessing);

  debug?.("OAuth tokens successfully processed");

  return processedTokens as TokensFromSignIn;
}

async function clearInternal() {
  const cfg = configure();
  const { debug } = cfg;

  debug?.("Clearing OAuth storage keys");
  await cfg.storage.removeItem(STATE_KEY);
  await cfg.storage.removeItem(PKCE_KEY);
  await cfg.storage.removeItem(OAUTH_IN_PROGRESS_KEY);
  debug?.("OAuth storage keys cleared");
}

async function clear() {
  const cfg = configure();
  const { debug } = cfg;
  const oauthLockKey = `Passwordless.${cfg.clientId}.oauthLock`;

  debug?.("🔒 [OAuth] Acquiring lock for clearing OAuth state");

  try {
    await withStorageLock(oauthLockKey, async () => clearInternal());
  } catch (error) {
    if (error instanceof LockTimeoutError) {
      debug?.(
        "⏱️ [OAuth] Lock timeout during clear - another OAuth operation is in progress"
      );
      throw new Error(
        "Cannot clear OAuth state: another OAuth operation is in progress. Please try again."
      );
    } else {
      throw error;
    }
  }
}

// Utility re-exports for other modules
export { generateRandomString } from "./oauthUtil.js";
