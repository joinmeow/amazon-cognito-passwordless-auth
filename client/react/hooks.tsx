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
import { signOut } from "../common.js";
import {
  parseJwtPayload,
  setTimeoutWallClock,
  bufferToBase64,
} from "../util.js";
import {
  fido2CreateCredential,
  fido2DeleteCredential,
  fido2ListCredentials,
  fido2UpdateCredential,
  StoredCredential,
  authenticateWithFido2,
} from "../fido2.js";
import { authenticateWithSRP } from "../srp.js";
import { authenticateWithPlaintextPassword } from "../plaintext.js";
import { configure } from "../config.js";
import {
  retrieveTokens,
  storeDeviceKey,
  getRememberedDevice,
  setRememberedDevice,
  TokensFromStorage,
} from "../storage.js";
import {
  BusyState,
  IdleState,
  busyState,
  TokensFromRefresh,
  TokensFromSignIn,
} from "../model.js";
import {
  scheduleRefresh,
  refreshTokens,
  forceRefreshTokens,
} from "../refresh.js";
import {
  CognitoAccessTokenPayload,
  CognitoIdTokenPayload,
} from "../jwt-model.js";
import {
  verifySoftwareTokenForCurrentUser as verifySoftwareTokenForCurrentUserApi,
  associateSoftwareTokenForCurrentUser as associateSoftwareTokenForCurrentUserApi,
  confirmDevice as confirmDeviceApi,
  updateDeviceStatus,
  forgetDevice as forgetDeviceApi,
  getUser,
} from "../cognito-api.js";
import React, {
  useState,
  useEffect,
  useContext,
  useCallback,
  useMemo,
  useRef,
  useReducer,
  ErrorInfo,
} from "react";
import { signInWithRedirect as hostedSignInWithRedirect } from "../hosted-oauth.js";

const PasswordlessContext = React.createContext<UsePasswordless | undefined>(
  undefined
);

/** React hook that provides convenient access to the Passwordless lib's features */
export function usePasswordless() {
  const context = useContext(PasswordlessContext);
  if (!context) {
    throw new Error(
      "The PasswordlessContextProvider must be added above this consumer in the React component tree"
    );
  }
  return context;
}

const LocalUserCacheContext = React.createContext<
  UseLocalUserCache | undefined
>(undefined);

/** React hook that stores and gives access to the last 10 signed in users (from your configured storage) */
export function useLocalUserCache() {
  const context = useContext(LocalUserCacheContext);
  if (!context) {
    throw new Error(
      "The localUserCache must be enabled in the PasswordlessContextProvider: <PasswordlessContextProvider enableLocalUserCache={true}>"
    );
  }
  return context;
}

/** Simple error boundary to catch hook failures */
class PasswordlessErrorBoundary extends React.Component<
  { children: React.ReactNode; fallback?: React.ReactNode },
  { hasError: boolean; error?: Error }
> {
  constructor(props: {
    children: React.ReactNode;
    fallback?: React.ReactNode;
  }) {
    super(props);
    this.state = { hasError: false };
  }

  static getDerivedStateFromError(error: Error) {
    return { hasError: true, error };
  }

  componentDidCatch(error: Error, errorInfo: ErrorInfo) {
    const { debug } = configure();
    debug?.("PasswordlessErrorBoundary caught error:", error, errorInfo);
  }

  render() {
    if (this.state.hasError) {
      return (
        this.props.fallback || (
          <div>
            <h2>Authentication Error</h2>
            <p>Something went wrong with the authentication system.</p>
            <details>
              <summary>Error Details</summary>
              <pre>{this.state.error?.message}</pre>
            </details>
          </div>
        )
      );
    }

    return this.props.children;
  }
}

export const PasswordlessContextProvider = (props: {
  children: React.ReactNode;
  enableLocalUserCache?: boolean;
  errorFallback?: React.ReactNode;
}) => {
  const passwordlessValue = _usePasswordless();

  // Memoize the context value to prevent unnecessary re-renders
  const memoizedValue = useMemo(
    () => passwordlessValue,
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [
      // State values that might change
      passwordlessValue.tokens,
      passwordlessValue.tokensParsed,
      passwordlessValue.isRefreshingTokens,
      passwordlessValue.lastError,
      passwordlessValue.signingInStatus,
      passwordlessValue.busy,
      passwordlessValue.signInStatus,
      passwordlessValue.userVerifyingPlatformAuthenticatorAvailable,
      passwordlessValue.fido2Credentials,
      passwordlessValue.creatingCredential,
      passwordlessValue.deviceKey,
      passwordlessValue.totpMfaStatus,
      passwordlessValue.timeSinceLastActivityMs,
      passwordlessValue.timeSinceLastActivitySeconds,
      passwordlessValue.authMethod,
      // Functions are already memoized with useCallback, so they're stable
      // We don't need to include them in dependencies
    ]
  );

  return (
    <PasswordlessErrorBoundary fallback={props.errorFallback}>
      <PasswordlessContext.Provider value={memoizedValue}>
        {props.enableLocalUserCache ? (
          <LocalUserCacheContextProvider errorFallback={props.errorFallback}>
            {props.children}
          </LocalUserCacheContextProvider>
        ) : (
          props.children
        )}
      </PasswordlessContext.Provider>
    </PasswordlessErrorBoundary>
  );
};

const LocalUserCacheContextProvider = (props: {
  children: React.ReactNode;
  errorFallback?: React.ReactNode;
}) => {
  const localUserCacheValue = _useLocalUserCache();

  // Memoize the context value to prevent unnecessary re-renders
  const memoizedValue = useMemo(
    () => localUserCacheValue,
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [
      localUserCacheValue.currentUser,
      localUserCacheValue.lastSignedInUsers,
      localUserCacheValue.signingInStatus,
      localUserCacheValue.authMethod,
      // Functions are already memoized with useCallback, so they're stable
    ]
  );

  return (
    <LocalUserCacheContext.Provider value={memoizedValue}>
      <PasswordlessErrorBoundary fallback={props.errorFallback}>
        {props.children}
      </PasswordlessErrorBoundary>
    </LocalUserCacheContext.Provider>
  );
};

/** A FIDO2 credential (e.g. Face ID or Touch), with convenient methods for updating and deleting */
type Fido2Credential = StoredCredential & {
  /** Update the friendly name of the credential */
  update: (update: { friendlyName: string }) => Promise<void>;
  /** Delete the credential */
  delete: () => Promise<void>;
  /** The credential is currently being updated or deleted */
  busy: boolean;
};

type UsePasswordless = ReturnType<typeof _usePasswordless>;

// Define state shape for useReducer
interface PasswordlessState {
  signingInStatus: BusyState | IdleState;
  initiallyRetrievingTokensFromStorage: boolean;
  tokens?: TokensFromStorage;
  tokensParsed?: {
    idToken: CognitoIdTokenPayload;
    accessToken: CognitoAccessTokenPayload;
    expireAt: Date;
  };
  lastError?: Error;
  userVerifyingPlatformAuthenticatorAvailable?: boolean;
  creatingCredential: boolean;
  fido2Credentials?: Fido2Credential[];
  deviceKey: string | null;
  isSchedulingRefresh?: boolean;
  isRefreshingTokens?: boolean;
  recheckSignInStatus: number;
  authMethod?: "SRP" | "FIDO2" | "PLAINTEXT" | "REDIRECT";
  totpMfaStatus: {
    enabled: boolean;
    preferred: boolean;
    availableMfaTypes: string[];
  };
  lastActivityAt: number;
  nowTick: number;
  isAttemptingExpiredTokenRefresh: boolean;
}

// Define action types
type PasswordlessAction =
  | { type: "SET_SIGNING_STATUS"; payload: BusyState | IdleState }
  | { type: "SET_INITIAL_LOADING"; payload: boolean }
  | { type: "SET_TOKENS"; payload: TokensFromStorage | undefined }
  | { type: "SET_TOKENS_PARSED"; payload: PasswordlessState["tokensParsed"] }
  | { type: "SET_ERROR"; payload: Error | undefined }
  | { type: "SET_PLATFORM_AUTHENTICATOR"; payload: boolean }
  | { type: "SET_CREATING_CREDENTIAL"; payload: boolean }
  | { type: "SET_FIDO2_CREDENTIALS"; payload: Fido2Credential[] | undefined }
  | {
      type: "UPDATE_FIDO2_CREDENTIAL";
      payload: { credentialId: string } & Partial<Fido2Credential>;
    }
  | { type: "DELETE_FIDO2_CREDENTIAL"; payload: string }
  | { type: "SET_DEVICE_KEY"; payload: string | null }
  | {
      type: "SET_REFRESH_STATUS";
      isScheduling?: boolean;
      isRefreshing?: boolean;
    }
  | { type: "INCREMENT_RECHECK_STATUS" }
  | { type: "SET_AUTH_METHOD"; payload: PasswordlessState["authMethod"] }
  | { type: "SET_TOTP_MFA_STATUS"; payload: PasswordlessState["totpMfaStatus"] }
  | { type: "SET_LAST_ACTIVITY"; payload: number }
  | { type: "SET_NOW_TICK"; payload: number }
  | { type: "SET_ATTEMPTING_EXPIRED_REFRESH"; payload: boolean }
  | { type: "SIGN_OUT" };

// Initial state
const initialPasswordlessState: PasswordlessState = {
  signingInStatus: "SIGNED_OUT",
  initiallyRetrievingTokensFromStorage: true,
  creatingCredential: false,
  deviceKey: null,
  recheckSignInStatus: 0,
  totpMfaStatus: {
    enabled: false,
    preferred: false,
    availableMfaTypes: [],
  },
  lastActivityAt: Date.now(),
  nowTick: Date.now(),
  isAttemptingExpiredTokenRefresh: false,
};

// Reducer function
function passwordlessReducer(
  state: PasswordlessState,
  action: PasswordlessAction
): PasswordlessState {
  switch (action.type) {
    case "SET_SIGNING_STATUS":
      return { ...state, signingInStatus: action.payload };

    case "SET_INITIAL_LOADING":
      return { ...state, initiallyRetrievingTokensFromStorage: action.payload };

    case "SET_TOKENS":
      return { ...state, tokens: action.payload };

    case "SET_TOKENS_PARSED":
      return { ...state, tokensParsed: action.payload };

    case "SET_ERROR":
      return { ...state, lastError: action.payload };

    case "SET_PLATFORM_AUTHENTICATOR":
      return {
        ...state,
        userVerifyingPlatformAuthenticatorAvailable: action.payload,
      };

    case "SET_CREATING_CREDENTIAL":
      return { ...state, creatingCredential: action.payload };

    case "SET_FIDO2_CREDENTIALS":
      return { ...state, fido2Credentials: action.payload };

    case "UPDATE_FIDO2_CREDENTIAL": {
      if (!state.fido2Credentials) return state;
      const index = state.fido2Credentials.findIndex(
        (c) => c.credentialId === action.payload.credentialId
      );
      if (index === -1) return state;
      const updated = [...state.fido2Credentials];
      // eslint-disable-next-line security/detect-object-injection
      updated[index] = { ...updated[index], ...action.payload };
      return { ...state, fido2Credentials: updated };
    }

    case "DELETE_FIDO2_CREDENTIAL":
      return {
        ...state,
        fido2Credentials: state.fido2Credentials?.filter(
          (c) => c.credentialId !== action.payload
        ),
      };

    case "SET_DEVICE_KEY":
      return { ...state, deviceKey: action.payload };

    case "SET_REFRESH_STATUS":
      return {
        ...state,
        ...(action.isScheduling !== undefined && {
          isSchedulingRefresh: action.isScheduling,
        }),
        ...(action.isRefreshing !== undefined && {
          isRefreshingTokens: action.isRefreshing,
        }),
      };

    case "INCREMENT_RECHECK_STATUS":
      return { ...state, recheckSignInStatus: state.recheckSignInStatus + 1 };

    case "SET_AUTH_METHOD":
      return { ...state, authMethod: action.payload };

    case "SET_TOTP_MFA_STATUS":
      return { ...state, totpMfaStatus: action.payload };

    case "SET_LAST_ACTIVITY":
      return { ...state, lastActivityAt: action.payload };

    case "SET_NOW_TICK":
      return { ...state, nowTick: action.payload };

    case "SET_ATTEMPTING_EXPIRED_REFRESH":
      return { ...state, isAttemptingExpiredTokenRefresh: action.payload };

    case "SIGN_OUT":
      return {
        ...initialPasswordlessState,
        signingInStatus: "SIGNED_OUT",
        initiallyRetrievingTokensFromStorage: false,
        userVerifyingPlatformAuthenticatorAvailable:
          state.userVerifyingPlatformAuthenticatorAvailable,
      };

    default:
      return state;
  }
}

function _usePasswordless() {
  // Use reducer instead of multiple useState calls
  const [state, dispatch] = useReducer(
    passwordlessReducer,
    initialPasswordlessState
  );

  // Destructure commonly used values from state for convenience
  const {
    signingInStatus,
    initiallyRetrievingTokensFromStorage,
    tokens,
    tokensParsed,
    lastError,
    userVerifyingPlatformAuthenticatorAvailable,
    creatingCredential,
    fido2Credentials,
    deviceKey,
    isSchedulingRefresh,
    isRefreshingTokens,
    recheckSignInStatus,
    authMethod,
    totpMfaStatus,
    lastActivityAt,
    nowTick,
    isAttemptingExpiredTokenRefresh,
  } = state;

  // Helper functions for common dispatch actions
  const setSigninInStatus = useCallback((status: BusyState | IdleState) => {
    dispatch({ type: "SET_SIGNING_STATUS", payload: status });
  }, []);

  const setLastError = useCallback((error: Error | undefined) => {
    dispatch({ type: "SET_ERROR", payload: error });
  }, []);

  const _setTokens = useCallback((tokens: TokensFromStorage | undefined) => {
    dispatch({ type: "SET_TOKENS", payload: tokens });
  }, []);

  const setTokensParsed = useCallback(
    (parsed: PasswordlessState["tokensParsed"]) => {
      dispatch({ type: "SET_TOKENS_PARSED", payload: parsed });
    },
    []
  );

  const setIsRefreshingTokens = useCallback((isRefreshing: boolean) => {
    dispatch({ type: "SET_REFRESH_STATUS", isRefreshing });
  }, []);

  // Unused - commented out to fix ESLint warning
  // const setDeviceKey = useCallback((key: string | null) => {
  //   dispatch({ type: "SET_DEVICE_KEY", payload: key });
  // }, []);

  // const setFido2Credentials = useCallback(
  //   (credentials: Fido2Credential[] | undefined) => {
  //     dispatch({ type: "SET_FIDO2_CREDENTIALS", payload: credentials });
  //   },
  //   []
  // );

  /** Translate authMethod → the corresponding *SIGNED_IN_WITH_* status */
  const signedInStatusForAuth = useCallback(
    (
      method?: "SRP" | "FIDO2" | "PLAINTEXT" | "REDIRECT"
    ): BusyState | IdleState | undefined => {
      switch (method) {
        case "REDIRECT":
          return "SIGNED_IN_WITH_REDIRECT";
        case "SRP":
          return "SIGNED_IN_WITH_SRP_PASSWORD";
        case "PLAINTEXT":
          return "SIGNED_IN_WITH_PLAINTEXT_PASSWORD";
        case "FIDO2":
          return "SIGNED_IN_WITH_FIDO2";
        default:
          return undefined;
      }
    },
    []
  );

  const updateFido2Credential = useCallback(
    (update: { credentialId: string } & Partial<Fido2Credential>) =>
      dispatch({ type: "UPDATE_FIDO2_CREDENTIAL", payload: update }),
    []
  );
  const deleteFido2Credential = useCallback(
    (credentialId: string) =>
      dispatch({ type: "DELETE_FIDO2_CREDENTIAL", payload: credentialId }),
    []
  );

  // Get activity tracking configuration
  // Note: We call configure() on each render to ensure we get the latest config
  // This is acceptable since configure() is lightweight and config changes are rare
  const { tokenRefresh } = configure();
  const useActivityTracking = tokenRefresh?.useActivityTracking ?? false;

  // 1️⃣  Attach lightweight listeners to detect user activity (only if activity tracking is enabled)
  useEffect(() => {
    if (
      !useActivityTracking ||
      typeof globalThis.addEventListener === "undefined"
    )
      return;
    const activityHandler = () =>
      dispatch({ type: "SET_LAST_ACTIVITY", payload: Date.now() });
    const events: (keyof WindowEventMap)[] = [
      "mousemove",
      "mousedown",
      "keydown",
      "scroll",
      "touchstart",
    ];
    events.forEach((evt) =>
      globalThis.addEventListener(evt, activityHandler, { passive: true })
    );
    return () =>
      events.forEach((evt) =>
        globalThis.removeEventListener(evt, activityHandler)
      );
  }, [useActivityTracking]);

  // 2️⃣  Keep an internal clock running so React renders every second and derived
  //      inactivity duration stays fresh. Only run if activity tracking is enabled.
  useEffect(() => {
    if (!useActivityTracking) return;
    const id = setInterval(
      () => dispatch({ type: "SET_NOW_TICK", payload: Date.now() }),
      1000
    );
    return () => clearInterval(id);
  }, [useActivityTracking]);

  /** Helper function for consumers – milliseconds since last activity */
  const timeSinceLastActivityMs = useActivityTracking
    ? nowTick - lastActivityAt
    : 0;

  // At component mount, check sign-in status
  useEffect(() => {
    setLastError(undefined);
  }, [setLastError]);
  const busy = busyState.includes(signingInStatus as BusyState);

  /**
   * Parse a fresh or cached token bundle and update the derived `tokensParsed` state.
   * Handles the special case where Hosted-UI/OAuth ("REDIRECT") flows may not return
   * an ID-token by synthesising a minimal one from the access-token claims so the
   * rest of the library can continue to treat the user as signed-in.
   */
  const parseAndSetTokens = useCallback(
    (tokens?: TokensFromStorage) => {
      if (!tokens) {
        setTokensParsed(undefined);
        return;
      }

      const { accessToken, expireAt, idToken } = tokens;

      // OAuth/Hosted-UI flow – ID-token can be missing
      if (accessToken && expireAt && tokens.authMethod === "REDIRECT") {
        try {
          const accessTokenParsed =
            parseJwtPayload<CognitoAccessTokenPayload>(accessToken);

          setTokensParsed({
            accessToken: accessTokenParsed,
            idToken: {
              sub: accessTokenParsed.sub,
              "cognito:username": accessTokenParsed.username,
              exp: accessTokenParsed.exp,
              iat: accessTokenParsed.iat,
              ...(idToken
                ? parseJwtPayload<CognitoIdTokenPayload>(idToken)
                : {}),
            } as CognitoIdTokenPayload,
            expireAt,
          });
        } catch (err) {
          const { debug } = configure();
          debug?.("Failed to parse tokens for OAuth flow:", err);
          setTokensParsed(undefined);
        }
        return;
      }

      // Standard flows – expect both access & ID token
      if (accessToken && expireAt) {
        try {
          if (idToken) {
            setTokensParsed({
              idToken: parseJwtPayload<CognitoIdTokenPayload>(idToken),
              accessToken:
                parseJwtPayload<CognitoAccessTokenPayload>(accessToken),
              expireAt,
            });
          } else {
            // Non-OAuth flows must provide an ID-token
            setTokensParsed(undefined);
          }
        } catch (err) {
          const { debug } = configure();
          debug?.("Failed to parse tokens:", err);
          setTokensParsed(undefined);
        }
      } else {
        setTokensParsed(undefined);
      }
    },
    [setTokensParsed]
  );

  // ---------------------------------------------------------------------------
  // ♻️  Schedule automatic token refresh and keep auth status stable
  // ---------------------------------------------------------------------------

  // At component mount, schedule token refresh
  const refreshToken = tokens?.refreshToken;
  const expireAtTime = tokens?.expireAt?.getTime();
  // Preserve the method used to obtain the current tokens so that we can
  // restore the correct *SIGNED_IN_WITH_* status after the background refresh.
  const authMethodFromTokens = tokens?.authMethod;

  useEffect(() => {
    if (!refreshToken) {
      return;
    }

    const abort = new AbortController();

    // Indicate that we are about to schedule or run a refresh operation
    dispatch({ type: "SET_REFRESH_STATUS", isScheduling: true });

    scheduleRefresh({
      abort: abort.signal,
      tokensCb: (newTokens) => {
        if (newTokens) {
          const merged = { ...tokens, ...newTokens } as TokensFromStorage;
          _setTokens(merged);
          parseAndSetTokens(merged);
        } else {
          _setTokens(undefined);
          parseAndSetTokens(undefined);
          dispatch({ type: "INCREMENT_RECHECK_STATUS" });
        }
      },
      isRefreshingCb: (isRefreshing) => {
        dispatch({ type: "SET_REFRESH_STATUS", isRefreshing: isRefreshing });

        const status = signedInStatusForAuth(authMethodFromTokens);
        status && setSigninInStatus(status);
      },
    })
      .catch((err) => {
        const { debug } = configure();
        debug?.("Failed to schedule token refresh:", err);

        const status = signedInStatusForAuth(authMethodFromTokens);
        status && setSigninInStatus(status);

        dispatch({ type: "INCREMENT_RECHECK_STATUS" });
      })
      .finally(() => {
        dispatch({ type: "SET_REFRESH_STATUS", isScheduling: false });
      });

    return () => abort.abort();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [
    // Only depend on specific token properties that should trigger refresh
    refreshToken,
    expireAtTime,
    authMethodFromTokens,
    // These don't depend on tokens changing, so safe to include
    signedInStatusForAuth,
    parseAndSetTokens,
    setSigninInStatus,
    _setTokens,
  ]);

  // Handle incomplete token bundle (edge-case: storage was tampered with)
  // Use ref to prevent circular dependencies
  const isHandlingIncompleteTokens = useRef(false);
  // Track which accessToken we have already used for GetUser, so we only
  // fetch MFA status once per token rotation (per page load).
  const lastFetchedMfaTokenRef = useRef<string | undefined>();

  // eslint-disable-next-line react-hooks/exhaustive-deps
  useEffect(() => {
    // Don't run if we're currently handling incomplete tokens to avoid loops
    if (isHandlingIncompleteTokens.current) return;

    if (
      tokens &&
      (!tokens.accessToken || !tokens.expireAt) &&
      !isRefreshingTokens &&
      !isSchedulingRefresh &&
      authMethod !== "SRP" &&
      signingInStatus !== "SIGNING_IN_WITH_PASSWORD" &&
      signingInStatus !== "SIGNED_IN_WITH_PASSWORD" &&
      signingInStatus !== "SIGNED_IN_WITH_REDIRECT" &&
      signingInStatus !== "STARTING_SIGN_IN_WITH_REDIRECT"
    ) {
      const { debug } = configure();
      debug?.("Detected incomplete tokens, attempting refresh");

      isHandlingIncompleteTokens.current = true;

      refreshTokens({
        tokensCb: (newTokens) => {
          if (newTokens) {
            const merged = { ...tokens, ...newTokens } as TokensFromStorage;
            parseAndSetTokens(merged);
            _setTokens(merged);
          } else {
            _setTokens(undefined);
            parseAndSetTokens(undefined);
            dispatch({ type: "INCREMENT_RECHECK_STATUS" });
          }
          isHandlingIncompleteTokens.current = false;
        },
        isRefreshingCb: setIsRefreshingTokens,
      }).catch(() => {
        _setTokens(undefined);
        parseAndSetTokens(undefined);
        dispatch({ type: "INCREMENT_RECHECK_STATUS" });
        isHandlingIncompleteTokens.current = false;
      });
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [
    // Be specific about token properties that indicate incomplete tokens
    tokens?.accessToken,
    tokens?.expireAt,
    isRefreshingTokens,
    isSchedulingRefresh,
    authMethod,
    signingInStatus,
    parseAndSetTokens,
    _setTokens,
    setIsRefreshingTokens,
  ]);

  // At component mount, load tokens from storage
  // eslint-disable-next-line react-hooks/exhaustive-deps
  useEffect(() => {
    const abortController = new AbortController();
    const { debug } = configure();

    // Retrieve tokens from storage
    retrieveTokens()
      .then((tokens) => {
        // Check if the operation was aborted
        if (abortController.signal.aborted) {
          debug?.("Token retrieval aborted - component unmounted");
          return;
        }

        // Process tokens only if not aborted
        _setTokens(tokens);
        parseAndSetTokens(tokens);

        // Update signing status for OAuth/REDIRECT tokens
        if (tokens?.authMethod === "REDIRECT") {
          debug?.(
            "Setting signingInStatus to SIGNED_IN_WITH_REDIRECT based on retrieved tokens"
          );
          setSigninInStatus("SIGNED_IN_WITH_REDIRECT");
        }
      })
      .catch((err) => {
        // Check if the operation was aborted before handling error
        if (abortController.signal.aborted) {
          debug?.(
            "Token retrieval error handling aborted - component unmounted"
          );
          return;
        }

        debug?.("Failed to retrieve tokens from storage:", err);
        // Make sure signInStatus gets recalculated on error
        dispatch({ type: "INCREMENT_RECHECK_STATUS" });
      })
      .finally(() => {
        // Check if the operation was aborted before final state update
        if (!abortController.signal.aborted) {
          dispatch({ type: "SET_INITIAL_LOADING", payload: false });
        }
      });

    // Cleanup function
    return () => {
      abortController.abort();
    };
  }, [parseAndSetTokens, _setTokens, setSigninInStatus]);

  // Give easy access to isUserVerifyingPlatformAuthenticatorAvailable
  useEffect(() => {
    if (typeof PublicKeyCredential !== "undefined") {
      const cancel = new AbortController();
      PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable()
        .then((res) => {
          if (!cancel.signal.aborted) {
            dispatch({ type: "SET_PLATFORM_AUTHENTICATOR", payload: res });
          }
        })
        .catch((err) => {
          const { debug } = configure();
          debug?.(
            "Failed to determine if a user verifying platform authenticator is available:",
            err
          );
        });

      // Return cleanup function from useEffect, not from promise
      return () => cancel.abort();
    } else {
      dispatch({ type: "SET_PLATFORM_AUTHENTICATOR", payload: false });
    }
  }, []);

  const toFido2Credential = useCallback(
    (credential: StoredCredential) => {
      return {
        ...credential,
        busy: false,
        update: async (update: { friendlyName: string }) => {
          updateFido2Credential({
            credentialId: credential.credentialId,
            busy: true,
          });
          return fido2UpdateCredential({
            ...update,
            credentialId: credential.credentialId,
          })
            .catch((err) => {
              updateFido2Credential({
                credentialId: credential.credentialId,
                busy: false,
              });
              throw err;
            })
            .then(() =>
              updateFido2Credential({
                ...update,
                credentialId: credential.credentialId,
                busy: false,
              })
            );
        },
        delete: async () => {
          updateFido2Credential({
            credentialId: credential.credentialId,
            busy: true,
          });
          return fido2DeleteCredential({
            credentialId: credential.credentialId,
          })
            .catch((err) => {
              updateFido2Credential({
                credentialId: credential.credentialId,
                busy: false,
              });
              throw err;
            })
            .then(() => deleteFido2Credential(credential.credentialId));
        },
      };
    },
    [deleteFido2Credential, updateFido2Credential]
  );

  // Determine sign-in status (single authoritative state for UI)
  // eslint-disable-next-line react-hooks/exhaustive-deps
  const signInStatus = useMemo(() => {
    // 1️⃣ Initial load – waiting for storage
    if (initiallyRetrievingTokensFromStorage) return "CHECKING";

    // 2️⃣ Library is busy signing in/out
    if (busyState.includes(signingInStatus as BusyState)) {
      return signingInStatus === "SIGNING_OUT" ? "SIGNING_OUT" : "SIGNING_IN";
    }

    // 3️⃣ Decide which expiry timestamp to use
    const isOAuth = tokens?.authMethod === "REDIRECT";
    const expiresAt: Date | undefined = isOAuth
      ? tokens?.expireAt
      : tokensParsed?.expireAt;

    // 3a) Still waiting for JWTs to be parsed – treat as signing in to avoid flicker
    if (!isOAuth && tokens && !tokensParsed) return "SIGNING_IN";

    // Missing tokens → not signed in
    if (!expiresAt) return "NOT_SIGNED_IN";

    // 4️⃣ Refresh in progress (including expired token refresh attempts)
    if (
      isSchedulingRefresh ||
      isRefreshingTokens ||
      isAttemptingExpiredTokenRefresh
    )
      return "REFRESHING_SIGN_IN";

    const now = Date.now();

    // 5️⃣ Tokens expired - attempt refresh before changing status
    if (now >= expiresAt.valueOf()) {
      // Check if we have a refresh token to attempt refresh
      if (tokens?.refreshToken && !isAttemptingExpiredTokenRefresh) {
        // Return refreshing status and trigger refresh in useEffect
        return "REFRESHING_SIGN_IN";
      }

      // No refresh token available or refresh already attempted and failed
      return "NOT_SIGNED_IN";
    }

    // 6️⃣ All good
    return "SIGNED_IN";
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [
    initiallyRetrievingTokensFromStorage,
    signingInStatus,
    tokens,
    tokensParsed,
    isSchedulingRefresh,
    isRefreshingTokens,
    recheckSignInStatus,
    isAttemptingExpiredTokenRefresh,
  ]);

  // Check signInStatus upon token expiry
  useEffect(() => {
    if (!tokens?.expireAt) return;
    const checkIn = tokens.expireAt.valueOf() - Date.now();
    if (checkIn < 0) return;
    return setTimeoutWallClock(() => {
      const { debug } = configure();
      debug?.(
        "Checking signInStatus as tokens have expired at:",
        tokens.expireAt?.toISOString()
      );
      dispatch({ type: "INCREMENT_RECHECK_STATUS" });
    }, checkIn);
  }, [tokens?.expireAt]);

  // Track FIDO2 authenticators for the user
  const isSignedIn =
    signInStatus === "SIGNED_IN" || signInStatus === "REFRESHING_SIGN_IN";
  const revalidateFido2Credentials = useCallback(() => {
    const { debug } = configure();

    // Only proceed when signed in (list credentials even after SRP)
    if (!isSignedIn) {
      debug?.("Not signed in, skipping credential listing");
      // Don't aggressively clear credentials - let sign out handle this
      // Return a no-op cleanup function to maintain consistent API
      return () => {};
    }

    // Only proceed with operations if signed in
    const cancel = new AbortController();

    // List credentials for signed-in user
    debug?.("Listing FIDO2 credentials");
    fido2ListCredentials()
      .then((res) => {
        if (!cancel.signal.aborted) {
          debug?.("Fetched FIDO2 credentials:", res.authenticators);
          dispatch({
            type: "SET_FIDO2_CREDENTIALS",
            payload: res.authenticators.map(toFido2Credential),
          });
        }
      })
      .catch((err) => {
        if (!cancel.signal.aborted) {
          debug?.("Failed to list credentials:", err);
        }
      });

    return () => cancel.abort();
  }, [isSignedIn, toFido2Credential]);

  useEffect(() => {
    const cleanup = revalidateFido2Credentials();
    return cleanup;
  }, [revalidateFido2Credentials]);

  // Track last fetch time to prevent spam
  const lastMfaFetchTimeRef = useRef<number>(0);
  const MFA_FETCH_COOLDOWN = 5000; // 5 second cooldown between fetches

  // Fetch TOTP MFA status when the user is signed in – with rate limiting
  useEffect(() => {
    // Early return if not signed in or no token
    if (!isSignedIn || !tokens?.accessToken) return;

    const now = Date.now();
    const timeSinceLastFetch = now - lastMfaFetchTimeRef.current;

    // Skip if we've already fetched MFA status for this token value
    if (tokens.accessToken === lastFetchedMfaTokenRef.current) return;

    // Skip if we fetched recently (within cooldown period)
    if (timeSinceLastFetch < MFA_FETCH_COOLDOWN) {
      const { debug } = configure();
      debug?.(
        `Skipping getUser call - cooldown active (${Math.round(
          (MFA_FETCH_COOLDOWN - timeSinceLastFetch) / 1000
        )}s remaining)`
      );
      return;
    }

    lastFetchedMfaTokenRef.current = tokens.accessToken;
    lastMfaFetchTimeRef.current = now;

    const abortController = new AbortController();

    // Get MFA settings for the signed-in user
    getUser({ accessToken: tokens.accessToken, abort: abortController.signal })
      .then((user) => {
        if (abortController.signal.aborted) return;

        // If we have a valid user object with MFA settings, use them
        if (user && typeof user === "object" && !("__type" in user)) {
          const hasMfa =
            user.UserMFASettingList?.includes("SOFTWARE_TOKEN_MFA") || false;
          const preferredMfa =
            user.PreferredMfaSetting === "SOFTWARE_TOKEN_MFA";

          dispatch({
            type: "SET_TOTP_MFA_STATUS",
            payload: {
              enabled: hasMfa,
              preferred: preferredMfa,
              availableMfaTypes: user.UserMFASettingList || [],
            },
          });
        } else {
          // Default to no MFA
          dispatch({
            type: "SET_TOTP_MFA_STATUS",
            payload: {
              enabled: false,
              preferred: false,
              availableMfaTypes: [],
            },
          });
        }
      })
      .catch(() => {
        if (abortController.signal.aborted) return;

        // On error we keep the previously known MFA status to avoid
        // falsely disabling security-gated UI. Log for debugging.
        const { debug } = configure();
        debug?.("getUser failed; retaining previous TOTP MFA status");
      });

    return () => {
      abortController.abort();
    };
  }, [isSignedIn, tokens?.accessToken]);

  useEffect(() => {
    const { debug } = configure();
    debug?.("fido2Credentials state updated:", fido2Credentials);
  }, [fido2Credentials]);

  /**
   * Replace the current token bundle with a fresh one – no merging.
   * Cognito rotates refresh-tokens, so keeping stale fields would be dangerous.
   */
  const updateTokens = useCallback(
    (next: TokensFromStorage | undefined) => {
      _setTokens(next);
      parseAndSetTokens(next);
    },
    [parseAndSetTokens, _setTokens]
  );

  // Handle expired token refresh when signInStatus is REFRESHING_SIGN_IN
  useEffect(() => {
    if (
      signInStatus === "REFRESHING_SIGN_IN" &&
      tokens?.refreshToken &&
      !isAttemptingExpiredTokenRefresh
    ) {
      const now = Date.now();
      const isOAuth = tokens?.authMethod === "REDIRECT";
      const expiresAt = isOAuth ? tokens?.expireAt : tokensParsed?.expireAt;

      // Only refresh if tokens are actually expired
      if (expiresAt && now >= expiresAt.valueOf()) {
        const { debug } = configure();
        debug?.("Tokens expired, attempting refresh");

        dispatch({ type: "SET_ATTEMPTING_EXPIRED_REFRESH", payload: true });

        // Use existing refreshTokens with built-in retry logic
        refreshTokens({
          tokensCb: (newTokens) => {
            dispatch({
              type: "SET_ATTEMPTING_EXPIRED_REFRESH",
              payload: false,
            });
            if (newTokens) {
              updateTokens(newTokens);
              debug?.("Successfully refreshed expired tokens");
            } else {
              debug?.("Failed to refresh expired tokens");
            }
          },
          isRefreshingCb: setIsRefreshingTokens,
          force: true,
        }).catch((err) => {
          const { debug } = configure();
          debug?.("Error refreshing expired tokens:", err);
          dispatch({ type: "SET_ATTEMPTING_EXPIRED_REFRESH", payload: false });
        });
      }
    }
  }, [
    signInStatus,
    tokens,
    tokensParsed,
    isAttemptingExpiredTokenRefresh,
    updateTokens,
    setIsRefreshingTokens,
  ]);

  // Reset expired token refresh flag when tokens change successfully
  useEffect(() => {
    if (tokens && isAttemptingExpiredTokenRefresh) {
      const { debug } = configure();
      debug?.("Tokens updated, resetting expired token refresh flag");
      dispatch({ type: "SET_ATTEMPTING_EXPIRED_REFRESH", payload: false });
    }
  }, [tokens, isAttemptingExpiredTokenRefresh]);

  return {
    /** The (raw) tokens: ID token, Access token and Refresh Token */
    tokens,
    /** The JSON parsed ID and Access token */
    tokensParsed,
    /** Is the UI currently refreshing tokens? */
    isRefreshingTokens,
    /** Execute (and reschedule) token refresh */
    refreshTokens: (abort?: AbortSignal) => {
      // Update signingInStatus to indicate refresh is in progress
      const { debug } = configure();
      debug?.("Manually refreshing tokens");

      // Set appropriate status based on auth method
      const status = signedInStatusForAuth(tokens?.authMethod);
      status && setSigninInStatus(status);

      return refreshTokens({
        abort,
        tokensCb: (newTokens) => {
          if (newTokens) {
            // Process tokens and update UI state with auth method
            updateTokens(newTokens);

            // Update signing status after refresh based on auth method
            const newStatus = signedInStatusForAuth(
              newTokens.authMethod ?? tokens?.authMethod
            );
            newStatus && setSigninInStatus(newStatus);
          }
          // Consistent return type - void
        },
        isRefreshingCb: setIsRefreshingTokens,
      });
    },
    /** Force an immediate token refresh regardless of current token state */
    forceRefreshTokens: (abort?: AbortSignal) => {
      // Update signingInStatus to indicate refresh is in progress
      const { debug } = configure();
      debug?.("Forcing immediate token refresh");

      // Set appropriate status based on auth method
      const status = signedInStatusForAuth(tokens?.authMethod);
      status && setSigninInStatus(status);

      return forceRefreshTokens({
        abort,
        tokensCb: (newTokens: TokensFromRefresh) => {
          if (newTokens) {
            // Process tokens and update UI state with auth method
            updateTokens(newTokens);

            // Update signing status after refresh based on auth method
            const newStatus = signedInStatusForAuth(
              newTokens.authMethod ?? tokens?.authMethod
            );
            newStatus && setSigninInStatus(newStatus);
          }
          // Consistent return type - void
        },
        isRefreshingCb: setIsRefreshingTokens,
      });
    },
    /** Mark the user as active to potentially trigger token refresh */
    markUserActive: () => {
      if (!useActivityTracking) {
        // Provide feedback that activity tracking is disabled
        const { debug } = configure();
        debug?.("markUserActive called but activity tracking is disabled");
        return;
      }
      dispatch({ type: "SET_LAST_ACTIVITY", payload: Date.now() });
      // Schedule a refresh if tokens exist but only if we're not currently refreshing
      if (tokens && !isRefreshingTokens) {
        // Using void to properly handle the promise
        void scheduleRefresh({
          tokensCb: (newTokens) => {
            if (newTokens) {
              updateTokens(newTokens);
            }
            // Consistent return type - void
          },
          isRefreshingCb: setIsRefreshingTokens,
        }).catch((err) => {
          const { debug } = configure();
          debug?.("Failed to schedule refresh on user activity:", err);
        });
      }
    },
    /** Last error that occured */
    lastError,
    /** The status of the most recent sign-in attempt */
    signingInStatus,
    /** Are we currently busy signing in or out? */
    busy,
    /**
     * The overall auth status, e.g. is the user signed in or not?
     * Use this field to show the relevant UI, e.g. render a sign-in page,
     * if the status equals "NOT_SIGNED_IN"
     */
    signInStatus,
    /** Is a user verifying platform authenticator available? E.g. Face ID or Touch */
    userVerifyingPlatformAuthenticatorAvailable,
    /** The user's registered FIDO2 credentials. Each credential provides `update` and `delete` methods */
    fido2Credentials,
    /** Are we currently creating a FIDO2 credential? */
    creatingCredential,
    /** The device key for remembered device authentication */
    deviceKey,
    /**
     * Confirm a device for trusted device authentication.
     * The device key must be available from a recent authentication response.
     */
    confirmDevice: async (deviceName: string) => {
      if (!tokens?.accessToken) {
        throw new Error("User must be signed in to confirm a device");
      }

      if (!deviceKey) {
        throw new Error("No device key available");
      }

      const { debug, crypto } = configure();
      debug?.("Confirming device:", deviceKey);

      // Generate device verifier config internally
      // Generate a random salt
      const saltBuffer = new Uint8Array(16);
      crypto.getRandomValues(saltBuffer);
      const salt = bufferToBase64(saltBuffer);

      // Generate a random password verifier
      const passwordVerifierBuffer = new Uint8Array(64);
      crypto.getRandomValues(passwordVerifierBuffer);
      const passwordVerifier = bufferToBase64(passwordVerifierBuffer);

      // Create device verifier config
      const deviceVerifierConfig = {
        passwordVerifier,
        salt,
      };

      const result = await confirmDeviceApi({
        accessToken: tokens.accessToken,
        deviceKey,
        deviceName,
        deviceSecretVerifierConfig: deviceVerifierConfig,
      });

      // If user confirmation is necessary, set device as remembered
      if (result.UserConfirmationNecessary) {
        debug?.(
          "User confirmation necessary for device, setting as remembered"
        );
        await updateDeviceStatus({
          accessToken: tokens.accessToken,
          deviceKey,
          deviceRememberedStatus: "remembered",
        });
      }

      // Ensure device key is stored in persistent storage
      await storeDeviceKey(tokens.username, deviceKey);

      return result;
    },
    /**
     * Update the status of a device (remembered or not_remembered).
     * Use this after getting userConfirmationNecessary=true in tokens
     * to set the device as remembered based on user choice.
     */
    updateDeviceStatus: async ({
      deviceKey,
      deviceRememberedStatus,
    }: {
      deviceKey: string;
      deviceRememberedStatus: "remembered" | "not_remembered";
    }) => {
      if (!tokens?.accessToken) {
        throw new Error("User must be signed in to update device status");
      }

      const { debug } = configure();
      debug?.(`Setting device ${deviceKey} as ${deviceRememberedStatus}`);

      await updateDeviceStatus({
        accessToken: tokens.accessToken,
        deviceKey,
        deviceRememberedStatus,
      });
    },
    /**
     * Forget a device to stop using it for trusted device authentication
     * Note that this is different from just clearing the local device key
     * as it also removes the device from the user's account on the server
     */
    forgetDevice: async (deviceKeyToForget: string = deviceKey || "") => {
      if (!tokens?.accessToken) {
        throw new Error("User must be signed in to forget a device");
      }

      if (!deviceKeyToForget) {
        throw new Error("No device key provided");
      }

      const { debug, storage, clientId } = configure();
      debug?.("Forgetting device:", deviceKeyToForget);

      await forgetDeviceApi({
        accessToken: tokens.accessToken,
        deviceKey: deviceKeyToForget,
      });

      // If forgetting the current device, clear it
      if (deviceKeyToForget === deviceKey) {
        // Remove the device key from storage
        const deviceKeyStorageKey = `Passwordless.${clientId}.deviceKey`;
        const result = storage.removeItem(deviceKeyStorageKey);
        if (result instanceof Promise) {
          await result;
        }

        // Clear deviceKey in state
        dispatch({ type: "SET_DEVICE_KEY", payload: null });
      }
    },
    /**
     * Clear the stored device key locally without removing it from the server
     */
    clearDeviceKey: () => {
      const { storage, clientId, debug } = configure();
      const deviceKeyStorageKey = `Passwordless.${clientId}.deviceKey`;

      const result = storage.removeItem(deviceKeyStorageKey);
      if (result instanceof Promise) {
        result.catch((err: Error) => {
          debug?.("Failed to remove device key from storage:", err);
        });
      }

      // Clear deviceKey in state
      dispatch({ type: "SET_DEVICE_KEY", payload: null });
    },
    /** Register a FIDO2 credential with the Relying Party */
    fido2CreateCredential: (
      ...args: Parameters<typeof fido2CreateCredential>
    ) => {
      dispatch({ type: "SET_CREATING_CREDENTIAL", payload: true });
      return fido2CreateCredential(...args)
        .then((storedCredential) => {
          const credential = toFido2Credential(storedCredential);
          dispatch({
            type: "SET_FIDO2_CREDENTIALS",
            payload: fido2Credentials
              ? [...fido2Credentials, credential]
              : [credential],
          });
          return storedCredential;
        })
        .finally(() =>
          dispatch({ type: "SET_CREATING_CREDENTIAL", payload: false })
        );
    },
    /** Sign out */
    signOut: (options?: { skipTokenRevocation?: boolean }) => {
      dispatch({ type: "SET_ERROR", payload: undefined });
      dispatch({ type: "SET_AUTH_METHOD", payload: undefined });
      const signingOut = signOut({
        statusCb: setSigninInStatus,
        tokensRemovedLocallyCb: () => {
          _setTokens(undefined);
          parseAndSetTokens(undefined);
          dispatch({ type: "SET_FIDO2_CREDENTIALS", payload: undefined });
        },
        currentStatus: signingInStatus,
        skipTokenRevocation: options?.skipTokenRevocation,
      });
      signingOut.signedOut.catch((error: Error) =>
        dispatch({ type: "SET_ERROR", payload: error })
      );
      return signingOut;
    },
    /** Sign in with FIDO2 (e.g. Face ID or Touch) */
    authenticateWithFido2: ({
      username,
      credentials,
      clientMetadata,
    }: {
      /** Username, alias (e-mail, phone number) */
      username?: string;
      credentials?: { id: string; transports?: AuthenticatorTransport[] }[];
      clientMetadata?: Record<string, string>;
    } = {}) => {
      const { debug } = configure();
      debug?.("Starting FIDO2 sign-in (hook)");
      dispatch({ type: "SET_ERROR", payload: undefined });
      dispatch({ type: "SET_AUTH_METHOD", payload: "FIDO2" });
      const signinIn = authenticateWithFido2({
        username,
        credentials,
        clientMetadata,
        statusCb: setSigninInStatus,
        tokensCb: async (newTokens) => {
          // 1) Update tokens in state and deviceKey
          updateTokens(newTokens);
          if (newTokens.deviceKey) {
            dispatch({ type: "SET_DEVICE_KEY", payload: newTokens.deviceKey });
          } else {
            try {
              const existing = await getRememberedDevice(newTokens.username);
              if (existing?.deviceKey) {
                dispatch({
                  type: "SET_DEVICE_KEY",
                  payload: existing.deviceKey,
                });
              }
            } catch {
              // ignore
            }
          }
          // 2) If a rememberDevice callback is provided and user confirmation is needed, prompt
          if (newTokens.userConfirmationNecessary) {
            try {
              if (newTokens.deviceKey && newTokens.accessToken) {
                debug?.(
                  `Fido2 sign-in setting device ${newTokens.deviceKey} as remembered`
                );
                await updateDeviceStatus({
                  accessToken: newTokens.accessToken,
                  deviceKey: newTokens.deviceKey,
                  deviceRememberedStatus: "remembered",
                });
                // Update local record
                const rec = await getRememberedDevice(newTokens.username);
                if (rec && rec.deviceKey === newTokens.deviceKey) {
                  await setRememberedDevice(newTokens.username, {
                    ...rec,
                    remembered: true,
                  });
                }
              } else {
                debug?.("User opted NOT to remember this device");
              }
            } catch (err) {
              debug?.("Failed while handling rememberDevice callback:", err);
            }
          }
          // 3) Refresh FIDO2 credentials list
          revalidateFido2Credentials();
        },
      });
      signinIn.signedIn.catch((error: Error) => {
        dispatch({ type: "SET_ERROR", payload: error });
      });
      return signinIn;
    },
    /** Sign in with username and password (using SRP: Secure Remote Password, where the password isn't sent over the wire) */
    authenticateWithSRP: ({
      username,
      password,
      smsMfaCode,
      otpMfaCode,
      newPassword,
      clientMetadata,
      rememberDevice,
    }: {
      /**
       * Username, or alias (e-mail, phone number)
       */
      username: string;
      password: string;
      smsMfaCode?: () => Promise<string>;
      otpMfaCode?: () => Promise<string>;
      /**
       * Provide a callback that resolves with a new password **when Cognito returns the
       * `NEW_PASSWORD_REQUIRED` challenge**. Returning a promise lets you prompt the user
       * only when necessary and keeps the authentication flow fully encapsulated.
       */
      newPassword?: () => Promise<string>;
      clientMetadata?: Record<string, string>;
      /**
       * Provide a callback that resolves to "true" if the user elected to remember
       * this device (e.g. after entering the MFA code). The function is only invoked
       * **after** Cognito tells us `UserConfirmationNecessary === true`.
       * Similar to `otpMfaCode`, returning a promise lets you prompt the user
       * during the authentication flow.
       */
      rememberDevice?: () => Promise<boolean>;
    }) => {
      const { debug } = configure();
      debug?.("Starting SRP authentication process");

      dispatch({ type: "SET_ERROR", payload: undefined });

      // Don't clear FIDO2 credentials - let the auth method control visibility
      // dispatch({ type: "SET_FIDO2_CREDENTIALS", payload: undefined });

      // Set auth method before authentication starts
      dispatch({ type: "SET_AUTH_METHOD", payload: "SRP" });

      const signinIn = authenticateWithSRP({
        username,
        password,
        smsMfaCode,
        otpMfaCode,
        newPassword,
        statusCb: (status) => {
          setSigninInStatus(status);
          // Ensure authMethod remains SRP throughout the authentication process
          if (status === "SIGNED_IN_WITH_SRP_PASSWORD") {
            debug?.(
              "SRP authentication successful, reinforcing SRP auth method"
            );
            dispatch({ type: "SET_AUTH_METHOD", payload: "SRP" });
            // Don't clear credentials here - auth method controls visibility
          }
        },
        tokensCb: async (newTokens: TokensFromSignIn) => {
          // Just update component state - processTokens handles storage and refresh
          updateTokens(newTokens);

          // Keep SRP-specific behavior for auth method
          debug?.(
            "Authentication completed, ensuring SRP auth method is preserved"
          );
          dispatch({ type: "SET_AUTH_METHOD", payload: "SRP" });
          // Don't clear credentials here - auth method controls visibility

          // Ensure device key is updated if present
          if (newTokens.deviceKey) {
            dispatch({ type: "SET_DEVICE_KEY", payload: newTokens.deviceKey });
          }

          // Force sign-in status update after setting tokens
          // For SRP auth, always use "SRP" to maintain consistency
          const status = signedInStatusForAuth("SRP");
          status && setSigninInStatus(status);

          // After successful authentication, handle remembered device flag if provided
          if (
            rememberDevice &&
            typeof rememberDevice === "function" &&
            newTokens.userConfirmationNecessary
          ) {
            try {
              const shouldRemember = await rememberDevice();
              if (
                shouldRemember &&
                newTokens.deviceKey &&
                newTokens.accessToken
              ) {
                const dKey = newTokens.deviceKey;
                const accTok = newTokens.accessToken;
                debug?.(`User opted to remember device ${dKey}`);
                await updateDeviceStatus({
                  accessToken: accTok,
                  deviceKey: dKey,
                  deviceRememberedStatus: "remembered",
                });

                // Update local remembered flag
                const rec = await getRememberedDevice(newTokens.username);
                if (rec && rec.deviceKey === dKey) {
                  await setRememberedDevice(newTokens.username, {
                    ...rec,
                    remembered: true,
                  });
                }
              } else {
                debug?.("User opted NOT to remember this device");
              }
            } catch (err) {
              debug?.("Failed while handling rememberDevice callback:", err);
            }
          }
        },
        clientMetadata: clientMetadata,
      });

      signinIn.signedIn
        .then(() => {
          debug?.("SRP authentication promise resolved successfully");
          // One final check to ensure auth method is still SRP after promise resolves
          dispatch({ type: "SET_AUTH_METHOD", payload: "SRP" });
        })
        .catch((error: Error) => {
          debug?.("SRP authentication failed:", error);
          // If authentication fails, make sure to clean up properly
          dispatch({ type: "SET_ERROR", payload: error });
          // Keep the auth method as SRP to prevent FIDO2 operations
          dispatch({ type: "SET_AUTH_METHOD", payload: "SRP" });
        });

      return signinIn;
    },
    /** Sign in with username and password (the password is sent in plaintext over the wire) */
    authenticateWithPlaintextPassword: ({
      username,
      password,
      smsMfaCode,
      otpMfaCode,
      clientMetadata,
      rememberDevice,
    }: {
      /**
       * Username, or alias (e-mail, phone number)
       */
      username: string;
      password: string;
      smsMfaCode?: () => Promise<string>;
      otpMfaCode?: () => Promise<string>;
      clientMetadata?: Record<string, string>;
      rememberDevice?: () => Promise<boolean>;
    }) => {
      dispatch({ type: "SET_ERROR", payload: undefined });
      dispatch({ type: "SET_AUTH_METHOD", payload: "PLAINTEXT" });
      const signinIn = authenticateWithPlaintextPassword({
        username,
        password,
        smsMfaCode,
        otpMfaCode,
        clientMetadata,
        statusCb: setSigninInStatus,
        tokensCb: async (newTokens: TokensFromSignIn) => {
          updateTokens(newTokens);

          // If rememberDevice callback requested and Cognito needs confirmation
          if (
            rememberDevice &&
            typeof rememberDevice === "function" &&
            newTokens.userConfirmationNecessary
          ) {
            try {
              const shouldRemember = await rememberDevice();
              if (
                shouldRemember &&
                newTokens.deviceKey &&
                newTokens.accessToken
              ) {
                const dKey = newTokens.deviceKey;
                const accTok = newTokens.accessToken;
                const { debug } = configure();
                debug?.(`Automatically remembering device ${dKey} (PLAINTEXT)`);
                await updateDeviceStatus({
                  accessToken: accTok,
                  deviceKey: dKey,
                  deviceRememberedStatus: "remembered",
                });

                // Update local remembered flag
                const rec = await getRememberedDevice(newTokens.username);
                if (rec && rec.deviceKey === dKey) {
                  await setRememberedDevice(newTokens.username, {
                    ...rec,
                    remembered: true,
                  });
                }
              }
            } catch (err) {
              const { debug } = configure();
              debug?.("Failed to remember device automatically:", err);
            }
          }
        },
      });
      signinIn.signedIn.catch((error: Error) =>
        dispatch({ type: "SET_ERROR", payload: error })
      );
      return signinIn;
    },
    /** The current status of TOTP MFA for the user */
    totpMfaStatus,
    /** Refresh the TOTP MFA status - use this after enabling/disabling MFA */
    refreshTotpMfaStatus: async () => {
      if (!tokens?.accessToken) return;

      try {
        const user = await getUser({ accessToken: tokens.accessToken });

        // Simple approach - if we have a valid user with MFA settings, use them
        if (user && typeof user === "object" && !("__type" in user)) {
          const hasMfa =
            user.UserMFASettingList?.includes("SOFTWARE_TOKEN_MFA") || false;
          const preferredMfa =
            user.PreferredMfaSetting === "SOFTWARE_TOKEN_MFA";

          dispatch({
            type: "SET_TOTP_MFA_STATUS",
            payload: {
              enabled: hasMfa,
              preferred: preferredMfa,
              availableMfaTypes: user.UserMFASettingList || [],
            },
          });
        } else {
          // Default to no MFA
          dispatch({
            type: "SET_TOTP_MFA_STATUS",
            payload: {
              enabled: false,
              preferred: false,
              availableMfaTypes: [],
            },
          });
        }
      } catch (error) {
        // Just default to no MFA on any error
        dispatch({
          type: "SET_TOTP_MFA_STATUS",
          payload: {
            enabled: false,
            preferred: false,
            availableMfaTypes: [],
          },
        });
      }
    },
    /** Milliseconds since the last user activity (mousemove, keydown, scroll, touch) */
    timeSinceLastActivityMs: useActivityTracking
      ? timeSinceLastActivityMs
      : null,
    /** Seconds (rounded) since the last user activity */
    timeSinceLastActivitySeconds: useActivityTracking
      ? Math.round(timeSinceLastActivityMs / 1000)
      : null,
    /** Re-load the latest token bundle from storage and push it into context */
    reloadTokensFromStorage: async () => {
      const latest = await retrieveTokens();
      updateTokens(latest);
    },
    /** Sign in via Cognito Hosted UI (redirect, e.g. Google) */
    signInWithRedirect: ({
      provider = "Google",
      customState,
      oauthParams,
    }: {
      provider?: string;
      customState?: string;
      oauthParams?: Record<string, string>;
    } = {}) => {
      const { debug } = configure();
      debug?.("Starting sign-in via Hosted UI redirect");
      dispatch({ type: "SET_ERROR", payload: undefined });
      dispatch({ type: "SET_AUTH_METHOD", payload: "REDIRECT" });
      dispatch({
        type: "SET_SIGNING_STATUS",
        payload: "STARTING_SIGN_IN_WITH_REDIRECT",
      });
      hostedSignInWithRedirect({ provider, customState, oauthParams }).catch(
        (err: unknown) => {
          debug?.("Failed to initiate redirect sign-in:", err);
          dispatch({
            type: "SET_ERROR",
            payload: err instanceof Error ? err : new Error(String(err)),
          });
          dispatch({
            type: "SET_SIGNING_STATUS",
            payload: "SIGNIN_WITH_REDIRECT_FAILED",
          });
        }
      );
    },
    /** The current authentication method used for these tokens */
    authMethod,
  };
}

/** User Details stored in your configured storage (e.g. localStorage) */
type StoredUser = {
  username: string;
  email?: string;
  useFido?: "YES" | "NO" | "ASK";
  credentials?: { id: string; transports?: AuthenticatorTransport[] }[];
  /** Last authentication method used by this user */
  authMethod?: "SRP" | "FIDO2" | "PLAINTEXT" | "REDIRECT";
};

/** Retrieve the last signed in users from your configured storage (e.g. localStorage) */
async function getLastSignedInUsers() {
  const { clientId, storage } = configure();
  const lastUsers = await storage.getItem(`Passwordless.${clientId}.lastUsers`);
  if (!lastUsers) return [];
  const users = JSON.parse(lastUsers) as StoredUser[];
  return users;
}

/** Clear the last signed in users from your configured storage (e.g. localStorage) */
async function clearLastSignedInUsers() {
  const { clientId, storage } = configure();
  await storage.removeItem(`Passwordless.${clientId}.lastUsers`);
}

/** Register a signed in user in your configured storage (e.g. localStorage) */
async function registerSignedInUser(user: StoredUser) {
  const { clientId, debug, storage } = configure();
  debug?.(`Registering user in storage: ${JSON.stringify(user)}`);
  const lastUsers = await getLastSignedInUsers();
  const index = lastUsers.findIndex(
    (lastUser) => lastUser.username === user.username
  );
  if (index !== -1) {
    lastUsers.splice(index, 1);
  }
  lastUsers.unshift(user);
  await storage.setItem(
    `Passwordless.${clientId}.lastUsers`,
    JSON.stringify(lastUsers.slice(0, 10))
  );
}

type UseLocalUserCache = ReturnType<typeof _useLocalUserCache>;
function _useLocalUserCache() {
  const {
    tokensParsed,
    creatingCredential,
    fido2Credentials,
    signingInStatus,
    authMethod,
  } = usePasswordless();

  const idToken = tokensParsed?.idToken;
  // FIDO2 credentials should be available regardless of auth method
  const hasFido2Credentials = fido2Credentials && !!fido2Credentials.length;
  const [lastSignedInUsers, setLastSignedInUsers] = useState<StoredUser[]>();
  const [currentUser, setCurrentUser] = useState<StoredUser>();
  const [fidoPreferenceOverride, setFidoPreferenceOverride] = useState<
    "YES" | "NO"
  >();

  // 1 populate lastSignedInUsers from local storage
  useEffect(() => {
    getLastSignedInUsers()
      .then(setLastSignedInUsers)
      .catch((err) => {
        const { debug } = configure();
        debug?.("Failed to determine last signed-in users:", err);
        // Set empty array as fallback to allow the UI to continue functioning
        setLastSignedInUsers([]);
      });
  }, []);

  // 2 populate currentUser from lastSignedInUsers OR init currentUser
  useEffect(() => {
    if (!idToken) {
      setCurrentUser(undefined);
      return;
    }
    const user: StoredUser = {
      username: idToken["cognito:username"],
      email:
        idToken.email && idToken.email_verified ? idToken.email : undefined,
      authMethod: authMethod,
    };
    if (lastSignedInUsers) {
      const found = lastSignedInUsers.find(
        (lastUser) =>
          lastUser.username && lastUser.username === idToken["cognito:username"]
      );
      if (found) {
        user.useFido = found.useFido;
        user.credentials = found.credentials;
        user.authMethod = found.authMethod ?? user.authMethod;
        if (!idToken.email_verified) {
          user.email = found.email;
        }
      }
    }
    setCurrentUser((state) =>
      JSON.stringify(state) === JSON.stringify(user) ? state : user
    );
  }, [lastSignedInUsers, idToken, authMethod]);

  // 3 If user is updated, store in lastSignedInUsers
  useEffect(() => {
    if (currentUser) {
      registerSignedInUser(currentUser).catch((err) => {
        const { debug } = configure();
        debug?.("Failed to register last signed-in user:", err);
      });
      setLastSignedInUsers((state) => {
        const update = [currentUser];
        for (const user of state ?? []) {
          if (user.username !== currentUser.username) {
            update.push(user);
          }
        }
        return JSON.stringify(state) === JSON.stringify(update)
          ? state
          : update;
      });
    }
  }, [currentUser]);

  const determineFido = useCallback(
    (user: StoredUser): "YES" | "NO" | "ASK" | "INDETERMINATE" => {
      // Disable FIDO2 UI for SRP auth sessions (credentials still available)
      if (authMethod === "SRP") {
        return "NO";
      }

      const { fido2 } = configure();
      if (!fido2) {
        return "NO";
      }
      if (hasFido2Credentials === undefined) {
        return "INDETERMINATE";
      }
      if (fidoPreferenceOverride) {
        return fidoPreferenceOverride;
      }
      if (user.useFido === "NO") {
        return "NO";
      }
      if (hasFido2Credentials) {
        return "YES";
      }
      if (creatingCredential) {
        return user.useFido ?? "INDETERMINATE";
      }
      return "ASK";
    },
    [
      creatingCredential,
      hasFido2Credentials,
      fidoPreferenceOverride,
      authMethod,
    ]
  );

  // 4 Update user FIDO preference based on auth method & credentials
  useEffect(() => {
    if (!currentUser) return;
    // For SRP sign-ins, explicitly disable FIDO2 UI behavior
    const useFido = authMethod === "SRP" ? "NO" : determineFido(currentUser);
    // Wait for credentials to be loaded before updating user state
    if (useFido === "INDETERMINATE") return;
    setCurrentUser((state) => {
      const update: StoredUser = {
        ...currentUser,
        useFido,
        authMethod: authMethod ?? currentUser.authMethod,
        // Always store credentials regardless of auth method
        credentials: fido2Credentials?.map((c) => ({
          id: c.credentialId,
          transports: c.transports,
        })),
      };
      return JSON.stringify(state) === JSON.stringify(update) ? state : update;
    });
  }, [currentUser, determineFido, fido2Credentials, authMethod]);

  // 5 reset state on signOut
  useEffect(() => {
    if (!currentUser) {
      setFidoPreferenceOverride(undefined);
    }
  }, [currentUser]);

  return {
    /** The current signed-in user */
    currentUser,
    /** Update the current user's FIDO2 preference */
    updateFidoPreference: ({ useFido }: { useFido: "YES" | "NO" }) => {
      // Users can always update their FIDO2 preference for future sign-ins
      setFidoPreferenceOverride(useFido);
    },
    /** The list of the 10 last signed-in users in your configured storage (e.g. localStorage) */
    lastSignedInUsers,
    /** Clear the last signed in users from your configured storage (e.g. localStorage) */
    clearLastSignedInUsers: () => {
      void clearLastSignedInUsers().catch((err) => {
        const { debug } = configure();
        debug?.("Failed to clear last signed-in users:", err);
      });
      setLastSignedInUsers(undefined);
    },
    /** The status of the most recent sign-in attempt */
    signingInStatus,
    /** The current authentication method */
    authMethod,
  };
}

/** React hook to turn state (or any variable) into a promise that can be awaited */
export function useAwaitableState<T>(state: T) {
  const resolve = useRef<(value: T) => void>();
  const reject = useRef<(reason: Error) => void>();
  const awaitable = useRef<Promise<T>>();
  const [awaited, setAwaited] = useState<{ value: T }>();
  const isMounted = useRef(true);

  const renewPromise = useCallback(() => {
    // Create a new promise without chaining to prevent memory leaks
    awaitable.current = new Promise<T>((_resolve, _reject) => {
      resolve.current = _resolve;
      reject.current = _reject;
    });
  }, []);

  // Initial setup
  useEffect(() => {
    renewPromise();
  }, [renewPromise]);

  // Reset awaited when state changes
  useEffect(() => setAwaited(undefined), [state]);

  // Cleanup on unmount
  useEffect(() => {
    return () => {
      isMounted.current = false;
      // Clear references to prevent memory leaks
      resolve.current = undefined;
      reject.current = undefined;
      awaitable.current = undefined;
    };
  }, []);

  return {
    /** Call to get the current awaitable (promise) */
    awaitable: () => awaitable.current!,
    /** Resolve the current awaitable (promise) with the current value of state */
    resolve: () => {
      if (resolve.current && isMounted.current) {
        const currentResolve = resolve.current;
        setAwaited({ value: state });
        currentResolve(state);
        renewPromise(); // Create new promise after resolving
      }
    },
    /** Reject the current awaitable (promise) */
    reject: (reason: Error) => {
      if (reject.current && isMounted.current) {
        const currentReject = reject.current;
        currentReject(reason);
        renewPromise(); // Create new promise after rejecting
      }
    },
    /** That value of awaitable (promise) once it resolves. This is undefined if (1) awaitable is not yet resolved or (2) the state has changed since awaitable was resolved */
    awaited,
  };
}

/** React hook to manage TOTP MFA setup and verification for a user */
export function useTotpMfa() {
  const { tokensParsed, totpMfaStatus, refreshTotpMfaStatus } =
    usePasswordless();
  const [secretCode, setSecretCode] = useState<string>();
  const [qrCodeUrl, setQrCodeUrl] = useState<string>();
  const [setupStatus, setSetupStatus] = useState<
    "IDLE" | "GENERATING" | "READY" | "VERIFYING" | "VERIFIED" | "ERROR"
  >("IDLE");
  const [errorMessage, setErrorMessage] = useState<string>();

  // Begin TOTP MFA setup
  const beginSetup = useCallback(async () => {
    setSetupStatus("GENERATING");
    setErrorMessage(undefined);
    const { debug } = configure();

    try {
      debug?.("Beginning TOTP MFA setup");
      const result = (await associateSoftwareTokenForCurrentUserApi()) as {
        SecretCode: string;
      };

      // Verify we got a valid secret code back
      if (!result || !result.SecretCode) {
        const errorMsg = "Failed to obtain secret code for TOTP setup";
        debug?.(errorMsg);
        setErrorMessage(errorMsg);
        setSetupStatus("ERROR");
        return null;
      }

      setSecretCode(result.SecretCode);
      debug?.("Secret code successfully obtained for TOTP MFA");

      // Generate QR code URL if we have a username from tokensParsed
      if (tokensParsed?.idToken && result.SecretCode) {
        const username =
          tokensParsed.idToken.email ||
          tokensParsed.idToken["cognito:username"] ||
          "";
        const { totp } = configure();
        // With the default value in the configure function, this will always have a value
        const issuer = totp?.issuer || "YourApp";
        const url = `otpauth://totp/${encodeURIComponent(issuer)}:${encodeURIComponent(username)}?secret=${encodeURIComponent(result.SecretCode)}&issuer=${encodeURIComponent(issuer)}`;
        setQrCodeUrl(url);
        debug?.("QR code URL generated successfully");
      } else {
        debug?.(
          "Could not generate QR code URL - missing token or username information"
        );
      }

      setSetupStatus("READY");
      return result;
    } catch (error) {
      const errorMsg = error instanceof Error ? error.message : String(error);
      debug?.("Error starting TOTP MFA setup:", errorMsg);
      setSetupStatus("ERROR");
      setErrorMessage(errorMsg);
      throw error;
    }
  }, [tokensParsed]);

  // Verify TOTP code to complete MFA setup
  const verifySetup = useCallback(
    async (code: string, deviceName?: string) => {
      setSetupStatus("VERIFYING");
      setErrorMessage(undefined);
      const { debug } = configure();

      try {
        debug?.(
          `Verifying TOTP code${deviceName ? ` for device "${deviceName}"` : ""}`
        );

        if (!code || code.length < 6) {
          const errorMsg = "Invalid TOTP code format";
          debug?.(errorMsg);
          setErrorMessage(errorMsg);
          setSetupStatus("ERROR");
          throw new Error(errorMsg);
        }

        const result = (await verifySoftwareTokenForCurrentUserApi({
          userCode: code,
          friendlyDeviceName: deviceName,
        })) as { Status: string };

        debug?.(`TOTP verification result: ${result?.Status || "Unknown"}`);

        if (!result || !result.Status) {
          const errorMsg = "Verification returned an invalid response";
          setErrorMessage(errorMsg);
          setSetupStatus("ERROR");
          throw new Error(errorMsg);
        }

        setSetupStatus(result.Status === "SUCCESS" ? "VERIFIED" : "ERROR");

        if (result.Status !== "SUCCESS") {
          const errorMsg = `Verification failed with status: ${result.Status}`;
          setErrorMessage(errorMsg);
          throw new Error(errorMsg);
        }

        // Refresh TOTP MFA status after successful verification
        debug?.("TOTP verification successful, refreshing MFA status");
        await refreshTotpMfaStatus();

        return result;
      } catch (error) {
        const errorMsg = error instanceof Error ? error.message : String(error);
        debug?.("Error during TOTP verification:", errorMsg);
        setSetupStatus("ERROR");
        setErrorMessage(errorMsg);
        throw error;
      }
    },
    [refreshTotpMfaStatus]
  );

  // Reset the setup process
  const resetSetup = useCallback(() => {
    const { debug } = configure();
    debug?.("Resetting TOTP MFA setup state");
    setSecretCode(undefined);
    setQrCodeUrl(undefined);
    setSetupStatus("IDLE");
    setErrorMessage(undefined);
  }, []);

  return {
    /** Current status of the TOTP MFA setup process */
    setupStatus,
    /** Secret code generated for TOTP setup (to display to user) */
    secretCode,
    /** QR code URL that can be turned into a QR code for scanning */
    qrCodeUrl,
    /** Error message if something went wrong */
    errorMessage,
    /** Start the TOTP MFA setup process */
    beginSetup,
    /** Verify the TOTP code to complete setup */
    verifySetup,
    /** Reset the setup state */
    resetSetup,
    /** Current status of TOTP MFA configuration for the user */
    totpMfaStatus,
  };
}
