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
  storeTokens,
  storeDeviceKey,
  getRememberedDevice,
  setRememberedDevice,
  TokensFromStorage,
  TokensToStore,
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
} from "react";

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

export const PasswordlessContextProvider = (props: {
  children: React.ReactNode;
  enableLocalUserCache?: boolean;
}) => {
  return (
    <PasswordlessContext.Provider value={_usePasswordless()}>
      {props.enableLocalUserCache ? (
        <LocalUserCacheContextProvider>
          {props.children}
        </LocalUserCacheContextProvider>
      ) : (
        props.children
      )}
    </PasswordlessContext.Provider>
  );
};

const LocalUserCacheContextProvider = (props: {
  children: React.ReactNode;
}) => {
  return (
    <LocalUserCacheContext.Provider value={_useLocalUserCache()}>
      {props.children}
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

function _usePasswordless() {
  const [signingInStatus, setSigninInStatus] = useState<BusyState | IdleState>(
    "SIGNED_OUT"
  );
  const [
    initiallyRetrievingTokensFromStorage,
    setInitiallyRetrievingTokensFromStorage,
  ] = useState(true);
  const [tokens, _setTokens] = useState<TokensFromStorage>();
  const [tokensParsed, setTokensParsed] = useState<{
    idToken: CognitoIdTokenPayload;
    accessToken: CognitoAccessTokenPayload;
    expireAt: Date;
  }>();
  const setTokens: typeof _setTokens = useCallback((reactSetStateAction) => {
    _setTokens((prevState) => {
      const newTokens =
        typeof reactSetStateAction === "function"
          ? reactSetStateAction(prevState)
          : reactSetStateAction;
      const { idToken, accessToken, expireAt } = newTokens ?? {};
      if (idToken && accessToken && expireAt) {
        setTokensParsed({
          idToken: parseJwtPayload<CognitoIdTokenPayload>(idToken),
          accessToken: parseJwtPayload<CognitoAccessTokenPayload>(accessToken),
          expireAt,
        });
      } else {
        setTokensParsed(undefined);
      }
      return newTokens;
    });
  }, []);
  const [lastError, setLastError] = useState<Error>();
  const [
    userVerifyingPlatformAuthenticatorAvailable,
    setUserVerifyingPlatformAuthenticatorAvailable,
  ] = useState<boolean>();
  const [creatingCredential, setCreatingCredential] = useState(false);
  const [fido2Credentials, setFido2Credentials] = useState<Fido2Credential[]>();
  const [deviceKey, setDeviceKey] = useState<string | null>(() => {
    // Will be populated when tokens are loaded during component initialization
    return null;
  });
  const updateFido2Credential = useCallback(
    (update: { credentialId: string } & Partial<Fido2Credential>) =>
      setFido2Credentials((state) => {
        if (!state) return state;
        const index = state.findIndex(
          (i) => i.credentialId === update.credentialId
        );
        if (index === -1) return state;
        // eslint-disable-next-line security/detect-object-injection
        state[index] = { ...state[index], ...update };
        return [...state];
      }),
    []
  );
  const deleteFido2Credential = useCallback(
    (credentialId: string) =>
      setFido2Credentials((state) =>
        state?.filter(
          (remainingAuthenticator) =>
            credentialId !== remainingAuthenticator.credentialId
        )
      ),
    []
  );
  const [isSchedulingRefresh, setIsSchedulingRefresh] = useState<boolean>();
  const [isRefreshingTokens, setIsRefreshingTokens] = useState<boolean>();
  const [recheckSignInStatus, setRecheckSignInStatus] = useState(0);
  const [authMethod, setAuthMethod] = useState<
    "SRP" | "FIDO2" | "PLAINTEXT" | undefined
  >();
  const [totpMfaStatus, setTotpMfaStatus] = useState<{
    enabled: boolean;
    preferred: boolean;
    availableMfaTypes: string[];
  }>({
    enabled: false,
    preferred: false,
    availableMfaTypes: [],
  });
  /** Timestamp (ms) of the last detected user interaction */
  const [lastActivityAt, setLastActivityAt] = useState<number>(() =>
    Date.now()
  );

  /** Local clock tick (updates every second) so the UI can react to inactivity duration */
  const [nowTick, setNowTick] = useState<number>(() => Date.now());

  // 1️⃣  Attach lightweight listeners to detect user activity
  useEffect(() => {
    if (typeof globalThis.addEventListener === "undefined") return;
    const activityHandler = () => setLastActivityAt(Date.now());
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
  }, []);

  // 2️⃣  Keep an internal clock running so React renders every second and derived
  //      inactivity duration stays fresh. Very cheap (1-sec interval, cleared on unmount).
  useEffect(() => {
    const id = setInterval(() => setNowTick(Date.now()), 1000);
    return () => clearInterval(id);
  }, []);

  /** Helper function for consumers – milliseconds since last activity */
  const timeSinceLastActivityMs = nowTick - lastActivityAt;

  // At component mount, check sign-in status
  useEffect(() => {
    setLastError(undefined);
  }, []);
  const busy = busyState.includes(signingInStatus as BusyState);

  // Schedule token refresh
  const refreshToken = tokens?.refreshToken;
  const expireAtTime = tokens?.expireAt?.getTime();
  useEffect(() => {
    if (refreshToken) {
      const abort = new AbortController();
      scheduleRefresh({
        abort: abort.signal,
        // Just update component state - processTokens handles storage
        tokensCb: (newTokens) => {
          if (newTokens) {
            setTokens((tokens) => ({ ...tokens, ...newTokens }));
          } else {
            // When we get null/undefined tokens (invalid case), trigger a refresh of signInStatus
            setRecheckSignInStatus((s) => s + 1);
          }
        },
        isRefreshingCb: setIsRefreshingTokens,
      })
        .catch((err) => {
          const { debug } = configure();
          debug?.("Failed to schedule token refresh:", err);
          // Also force a recheck on errors
          setRecheckSignInStatus((s) => s + 1);
        })
        .finally(() => setIsSchedulingRefresh(false));
      return () => abort.abort();
    }
  }, [setTokens, refreshToken, expireAtTime]);

  // If we have some tokens, but not all, attempt a refresh
  // Should only happen in corner cases, e.g. a developer deleted some keys from storage
  // Skip this check if we're in the middle of SRP authentication process
  if (
    tokens &&
    (!tokens.idToken || !tokens.accessToken || !tokens.expireAt) &&
    !isRefreshingTokens &&
    !isSchedulingRefresh &&
    authMethod !== "SRP" &&
    signingInStatus !== "SIGNING_IN_WITH_PASSWORD" &&
    signingInStatus !== "SIGNED_IN_WITH_PASSWORD"
  ) {
    const { debug } = configure();
    debug?.("Detected incomplete tokens, attempting refresh");
    refreshTokens({
      // Just update component state - processTokens handles storage
      tokensCb: (newTokens) => {
        if (newTokens) {
          setTokens((tokens) => ({ ...tokens, ...newTokens }));
        } else {
          // If refresh fails completely, clear tokens and trigger signInStatus update
          setTokens(undefined);
          setRecheckSignInStatus((s) => s + 1);
        }
      },
      isRefreshingCb: setIsRefreshingTokens,
    }).catch(() => {
      setTokens(undefined);
      setRecheckSignInStatus((s) => s + 1);
    });
  }

  // At component mount, load tokens from storage
  useEffect(() => {
    // First, retrieve tokens from storage
    retrieveTokens()
      .then(setTokens)
      .catch((err) => {
        const { debug } = configure();
        debug?.("Failed to retrieve tokens from storage:", err);
        // Make sure signInStatus gets recalculated on error
        setRecheckSignInStatus((s) => s + 1);
      })
      .finally(() => setInitiallyRetrievingTokensFromStorage(false));
  }, [setTokens]);

  // Give easy access to isUserVerifyingPlatformAuthenticatorAvailable
  useEffect(() => {
    if (typeof PublicKeyCredential !== "undefined") {
      const cancel = new AbortController();
      PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable()
        .then((res) => {
          if (!cancel.signal.aborted) {
            setUserVerifyingPlatformAuthenticatorAvailable(res);
          }
          return () => cancel.abort();
        })
        .catch((err) => {
          const { debug } = configure();
          debug?.(
            "Failed to determine if a user verifying platform authenticator is available:",
            err
          );
        });
    } else {
      setUserVerifyingPlatformAuthenticatorAvailable(false);
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

  // Determine sign-in status
  const signInStatus = useMemo(() => {
    const { debug } = configure();
    debug?.(
      "Re-calculating signInStatus (recheckCount:",
      recheckSignInStatus,
      ")"
    );

    // ensure memo updates when tokens expire
    void recheckSignInStatus;
    // 1) Initial load
    if (initiallyRetrievingTokensFromStorage) {
      debug?.("signInStatus → CHECKING (initiallyRetrievingTokensFromStorage)");
      return "CHECKING" as const;
    }
    // 2) Any busy operation
    if (busyState.includes(signingInStatus as BusyState)) {
      if (signingInStatus === "SIGNING_OUT") {
        debug?.("signInStatus → SIGNING_OUT (busyState)");
        return "SIGNING_OUT" as const;
      }
      debug?.("signInStatus → SIGNING_IN (busyState)");
      return "SIGNING_IN" as const;
    }
    // 3) Not signed in if no valid tokens
    if (!tokensParsed) {
      debug?.("signInStatus → NOT_SIGNED_IN (no tokensParsed)");
      return "NOT_SIGNED_IN" as const;
    }
    // 4) Refresh in progress
    if (isSchedulingRefresh || isRefreshingTokens) {
      debug?.("signInStatus → REFRESHING_SIGN_IN");
      return "REFRESHING_SIGN_IN" as const;
    }
    // 5) Token expired
    if (tokensParsed.expireAt.valueOf() <= Date.now()) {
      debug?.("signInStatus → NOT_SIGNED_IN (token expired)");
      return "NOT_SIGNED_IN" as const;
    }
    // 6) Otherwise, we're signed in
    debug?.("signInStatus → SIGNED_IN");
    return "SIGNED_IN" as const;
  }, [
    initiallyRetrievingTokensFromStorage,
    signingInStatus,
    tokensParsed,
    isSchedulingRefresh,
    isRefreshingTokens,
    recheckSignInStatus,
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
      setRecheckSignInStatus((s) => s + 1);
    }, checkIn);
  }, [tokens?.expireAt]);

  // Track FIDO2 authenticators for the user
  const isSignedIn =
    signInStatus === "SIGNED_IN" || signInStatus === "REFRESHING_SIGN_IN";
  const revalidateFido2Credentials = () => {
    const { debug } = configure();

    // Only proceed when signed in (list credentials even after SRP)
    if (!isSignedIn) {
      debug?.("Not signed in, skipping credential listing");
      setFido2Credentials(undefined);
      return () => {};
    }

    // Only proceed with operations if signed in
    const cancel = new AbortController();
    // List credentials for signed-in user
    if (isSignedIn) {
      debug?.("Listing FIDO2 credentials");
      fido2ListCredentials()
        .then((res) => {
          if (!cancel.signal.aborted) {
            debug?.("Fetched FIDO2 credentials:", res.authenticators);
            setFido2Credentials(res.authenticators.map(toFido2Credential));
          }
        })
        .catch((err) => {
          debug?.("Failed to list credentials:", err);
        });
      return () => cancel.abort();
    }

    return () => {};
  };
  useEffect(revalidateFido2Credentials, [
    isSignedIn,
    toFido2Credential,
    authMethod,
  ]);

  // Fetch TOTP MFA status when the user is signed in
  useEffect(() => {
    if (!isSignedIn || !tokens?.accessToken) return;

    const abort = new AbortController();

    // Just try to get MFA settings, but don't make a big deal if they're not there
    getUser({ accessToken: tokens.accessToken, abort: abort.signal })
      .then((user) => {
        try {
          // If we have a valid user object with MFA settings, use them
          if (user && typeof user === "object" && !("__type" in user)) {
            const hasMfa =
              user.UserMFASettingList?.includes("SOFTWARE_TOKEN_MFA") || false;
            const preferredMfa =
              user.PreferredMfaSetting === "SOFTWARE_TOKEN_MFA";

            setTotpMfaStatus({
              enabled: hasMfa,
              preferred: preferredMfa,
              availableMfaTypes: user.UserMFASettingList || [],
            });
          } else {
            // Default to no MFA settings
            setTotpMfaStatus({
              enabled: false,
              preferred: false,
              availableMfaTypes: [],
            });
          }
        } catch (e) {
          // Just suppress errors and use default values
          setTotpMfaStatus({
            enabled: false,
            preferred: false,
            availableMfaTypes: [],
          });
        }
      })
      .catch(() => {
        // If anything fails, just default to no MFA settings
        setTotpMfaStatus({
          enabled: false,
          preferred: false,
          availableMfaTypes: [],
        });
      });

    return () => abort.abort();
  }, [isSignedIn, tokens?.accessToken]);

  useEffect(() => {
    const { debug } = configure();
    debug?.("fido2Credentials state updated:", fido2Credentials);
  }, [fido2Credentials]);

  return {
    /** The (raw) tokens: ID token, Access token and Refresh Token */
    tokens,
    /** The JSON parsed ID and Access token */
    tokensParsed,
    /** Is the UI currently refreshing tokens? */
    isRefreshingTokens,
    /** Execute (and reschedule) token refresh */
    refreshTokens: (abort?: AbortSignal) =>
      refreshTokens({
        abort,
        tokensCb: (newTokens) =>
          newTokens &&
          storeTokens(newTokens).then(() =>
            setTokens((tokens) => ({ ...tokens, ...newTokens }))
          ),
        isRefreshingCb: setIsRefreshingTokens,
      }),
    /** Force an immediate token refresh regardless of current token state */
    forceRefreshTokens: (abort?: AbortSignal) =>
      forceRefreshTokens({
        abort,
        tokensCb: (newTokens: TokensFromRefresh) => {
          if (newTokens) {
            return storeTokens(newTokens as TokensToStore).then(() =>
              setTokens((tokens) => ({ ...tokens, ...newTokens }))
            );
          }
          return Promise.resolve();
        },
        isRefreshingCb: setIsRefreshingTokens,
      }),
    /** Mark the user as active to potentially trigger token refresh */
    markUserActive: () => {
      setLastActivityAt(Date.now());
      // Schedule a refresh if tokens exist but only if we're not currently refreshing
      if (tokens && !isRefreshingTokens) {
        // Using void to properly handle the promise
        void scheduleRefresh({
          tokensCb: (newTokens) => {
            if (newTokens) {
              return storeTokens(newTokens as TokensToStore).then(() =>
                setTokens((tokens) => ({ ...tokens, ...newTokens }))
              );
            }
            return Promise.resolve();
          },
          isRefreshingCb: setIsRefreshingTokens,
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
        setDeviceKey(null);
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
      setDeviceKey(null);
    },
    /** Register a FIDO2 credential with the Relying Party */
    fido2CreateCredential: (
      ...args: Parameters<typeof fido2CreateCredential>
    ) => {
      setCreatingCredential(true);
      return fido2CreateCredential(...args)
        .then((storedCredential) => {
          setFido2Credentials((state) => {
            const credential = toFido2Credential(storedCredential);
            return state ? state.concat([credential]) : [credential];
          });
          return storedCredential;
        })
        .finally(() => setCreatingCredential(false));
    },
    /** Sign out */
    signOut: (options?: { skipTokenRevocation?: boolean }) => {
      setLastError(undefined);
      setAuthMethod(undefined);
      const signingOut = signOut({
        statusCb: setSigninInStatus,
        tokensRemovedLocallyCb: () => {
          setTokens(undefined);
          setTokensParsed(undefined);
          setFido2Credentials(undefined);
        },
        currentStatus: signingInStatus,
        skipTokenRevocation: options?.skipTokenRevocation,
      });
      signingOut.signedOut.catch((error: Error) => setLastError(error));
      return signingOut;
    },
    /**
     * Sign in with FIDO2 (e.g. Face ID or Touch)
     */
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
      setLastError(undefined);
      setAuthMethod("FIDO2");
      const signinIn = authenticateWithFido2({
        username,
        credentials,
        clientMetadata,
        statusCb: setSigninInStatus,
        tokensCb: async (newTokens) => {
          // 1) Update tokens in state and deviceKey
          setTokens(newTokens);
          if (newTokens.deviceKey) {
            setDeviceKey(newTokens.deviceKey);
          } else {
            try {
              const existing = await getRememberedDevice(newTokens.username);
              if (existing?.deviceKey) {
                setDeviceKey(existing.deviceKey);
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
        setLastError(error);
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

      setLastError(undefined);

      // Clear any existing FIDO2 credentials to prevent unwanted checks
      setFido2Credentials(undefined);

      // Set auth method before authentication starts
      setAuthMethod("SRP");

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
            setAuthMethod("SRP");
            // Explicitly clear FIDO2 credentials again to prevent any listing attempts
            setFido2Credentials(undefined);
          }
        },
        tokensCb: async (newTokens: TokensFromSignIn) => {
          // Just update component state - processTokens handles storage and refresh
          setTokens(newTokens);

          // Keep SRP-specific behavior for auth method
          debug?.(
            "Authentication completed, ensuring SRP auth method is preserved"
          );
          setAuthMethod("SRP");
          setFido2Credentials(undefined);

          // Ensure device key is updated if present
          if (newTokens.deviceKey) {
            setDeviceKey(newTokens.deviceKey);
          }

          // Force sign-in status update after setting tokens
          setSigninInStatus("SIGNED_IN_WITH_SRP_PASSWORD");

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
          setAuthMethod("SRP");
        })
        .catch((error: Error) => {
          debug?.("SRP authentication failed:", error);
          // If authentication fails, make sure to clean up properly
          setLastError(error);
          // Keep the auth method as SRP to prevent FIDO2 operations
          setAuthMethod("SRP");
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
      setLastError(undefined);
      setAuthMethod("PLAINTEXT");
      const signinIn = authenticateWithPlaintextPassword({
        username,
        password,
        smsMfaCode,
        otpMfaCode,
        clientMetadata,
        statusCb: setSigninInStatus,
        tokensCb: async (newTokens: TokensFromSignIn) => {
          setTokens(newTokens);

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
      signinIn.signedIn.catch((error: Error) => setLastError(error));
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

          setTotpMfaStatus({
            enabled: hasMfa,
            preferred: preferredMfa,
            availableMfaTypes: user.UserMFASettingList || [],
          });
        } else {
          // Default to no MFA
          setTotpMfaStatus({
            enabled: false,
            preferred: false,
            availableMfaTypes: [],
          });
        }
      } catch (error) {
        // Just default to no MFA on any error
        setTotpMfaStatus({
          enabled: false,
          preferred: false,
          availableMfaTypes: [],
        });
      }
    },
    /** Milliseconds since the last user activity (mousemove, keydown, scroll, touch) */
    timeSinceLastActivityMs,
    /** Seconds (rounded) since the last user activity */
    timeSinceLastActivitySeconds: Math.round(timeSinceLastActivityMs / 1000),
  };
}

/** User Details stored in your configured storage (e.g. localStorage) */
type StoredUser = {
  username: string;
  email?: string;
  useFido?: "YES" | "NO" | "ASK";
  credentials?: { id: string; transports?: AuthenticatorTransport[] }[];
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
  } = usePasswordless();

  // Access the authMethod directly from the parent context
  // We need to use another way to access the authMethod value
  // Since it's not exposed in the usePasswordless() return object
  // Let's create a local version in this hook
  const [authMethodLocal, setAuthMethodLocal] = useState<
    "SRP" | "FIDO2" | "PLAINTEXT" | undefined
  >();

  // Keep our local authMethod in sync with the main one by watching signingInStatus
  useEffect(() => {
    if (signingInStatus === "SIGNED_IN_WITH_SRP_PASSWORD") {
      setAuthMethodLocal("SRP");
    } else if (signingInStatus === "SIGNED_IN_WITH_PLAINTEXT_PASSWORD") {
      setAuthMethodLocal("PLAINTEXT");
    } else if (signingInStatus === "SIGNED_IN_WITH_FIDO2") {
      setAuthMethodLocal("FIDO2");
    } else if (signingInStatus === "SIGNED_OUT") {
      setAuthMethodLocal(undefined);
    }
  }, [signingInStatus]);

  const idToken = tokensParsed?.idToken;
  // Only consider FIDO2 credentials if we're not using SRP auth
  const hasFido2Credentials =
    authMethodLocal !== "SRP" && fido2Credentials && !!fido2Credentials.length;
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
    };
    if (lastSignedInUsers) {
      const found = lastSignedInUsers.find(
        (lastUser) =>
          lastUser.username && lastUser.username === idToken["cognito:username"]
      );
      if (found) {
        user.useFido = found.useFido;
        user.credentials = found.credentials;
        if (!idToken.email_verified) {
          user.email = found.email;
        }
      }
    }
    setCurrentUser((state) =>
      JSON.stringify(state) === JSON.stringify(user) ? state : user
    );
  }, [lastSignedInUsers, idToken]);

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
      // Don't enable FIDO2 for SRP auth sessions
      if (authMethodLocal === "SRP") {
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
      authMethodLocal,
    ]
  );

  // 4 Update user FIDO preference based on auth method & credentials
  useEffect(() => {
    if (!currentUser) return;
    // For SRP sign-ins, explicitly disable FIDO2
    const useFido =
      authMethodLocal === "SRP" ? "NO" : determineFido(currentUser);
    if (useFido === "INDETERMINATE") return;
    setCurrentUser((state) => {
      const update: StoredUser = {
        ...currentUser,
        useFido,
        // Clear stored credentials on SRP; otherwise keep FIDO2 list
        credentials:
          authMethodLocal === "SRP"
            ? undefined
            : fido2Credentials?.map((c) => ({
                id: c.credentialId,
                transports: c.transports,
              })),
      };
      return JSON.stringify(state) === JSON.stringify(update) ? state : update;
    });
  }, [currentUser, determineFido, fido2Credentials, authMethodLocal]);

  // 5 reset state on signOut
  useEffect(() => {
    if (!currentUser) {
      setFidoPreferenceOverride(undefined);
      setAuthMethodLocal(undefined);
    }
  }, [currentUser]);

  return {
    /** The current signed-in user */
    currentUser,
    /** Update the current user's FIDO2 preference */
    updateFidoPreference: ({ useFido }: { useFido: "YES" | "NO" }) => {
      // Don't allow FIDO2 preference changes in SRP sessions
      if (authMethodLocal === "SRP" && useFido === "YES") {
        return;
      }
      setFidoPreferenceOverride(useFido);
    },
    /** The list of the 10 last signed-in users in your configured storage (e.g. localStorage) */
    lastSignedInUsers,
    /** Clear the last signed in users from your configured storage (e.g. localStorage) */
    clearLastSignedInUsers: () => {
      clearLastSignedInUsers().catch((err) => {
        const { debug } = configure();
        debug?.("Failed to clear last signed-in users:", err);
      });
      setLastSignedInUsers(undefined);
    },
    /** The status of the most recent sign-in attempt */
    signingInStatus,
    /** The current authentication method */
    authMethod: authMethodLocal,
  };
}
/** React hook to turn state (or any variable) into a promise that can be awaited */
export function useAwaitableState<T>(state: T) {
  const resolve = useRef<(value: T) => void>();
  const reject = useRef<(reason: Error) => void>();
  const awaitable = useRef<Promise<T>>();
  const [awaited, setAwaited] = useState<{ value: T }>();
  const renewPromise = useCallback(() => {
    awaitable.current = new Promise<T>((_resolve, _reject) => {
      resolve.current = _resolve;
      reject.current = _reject;
    })
      .then((value) => {
        setAwaited({ value });
        return value;
      })
      .finally(renewPromise);
  }, []);
  useEffect(renewPromise, [renewPromise]);
  useEffect(() => setAwaited(undefined), [state]);
  return {
    /** Call to get the current awaitable (promise) */
    awaitable: () => awaitable.current!,
    /** Resolve the current awaitable (promise) with the current value of state */
    resolve: () => resolve.current!(state),
    /** Reject the current awaitable (promise) */
    reject: (reason: Error) => reject.current!(reason),
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
          tokensParsed.idToken["cognito:username"] ||
          tokensParsed.idToken.email ||
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
