# Meow Cognito Passwordless Auth (Client)

A client-side library for implementing passwordless authentication with Amazon Cognito. This package provides the frontend implementation for various **secure** passwordless authentication methods:

- **FIDO2**: aka **WebAuthn**, i.e. sign in with Face, Touch, YubiKey, etc. This includes support for **Passkeys** (i.e. usernameless authentication).
- **Device Authentication**: allow users to authenticate with trusted devices after initial verification.
- **TOTP MFA**: support for Time-Based One-Time Password multi-factor authentication.

This is an opinionated fork of the [original Amazon Cognito Passwordless Auth solution](https://github.com/aws-samples/amazon-cognito-passwordless-auth), maintained by [@joinmeow](https://github.com/joinmeow). Unlike the original library, this fork focuses exclusively on secure authentication methods and eliminates less secure options, creating a more streamlined and security-focused implementation. This client-only version is intended for use with an already configured backend.

## Installation

This package is published on npm and can be installed directly:

```shell
npm install @joinmeow/cognito-passwordless-auth
```

Or with Yarn:

```shell
yarn add @joinmeow/cognito-passwordless-auth
```

## Usage

This library provides implementations for different frontend frameworks:

### Usage in (plain) Web

```javascript
import {
  Passwordless,
  initialize,
  signUp,
  confirmSignUp,
} from "@joinmeow/cognito-passwordless-auth";

// Configure the client
Passwordless.configure({
  userPoolId: "us-east-1_example",
  clientId: "abcdefghijklmnopqrstuvwxyz",
  // Other configuration parameters as needed
});

// Initialize (handles things like redirects)
initialize();

// Sign up a new user
await signUp({
  username: "user@example.com",
  password: "securePassword123",
  userAttributes: [
    { name: "email", value: "user@example.com" },
    { name: "name", value: "Jane Doe" },
  ],
});

// Confirm sign up with verification code
await confirmSignUp({
  username: "user@example.com",
  confirmationCode: "123456",
});

// Start the sign-in process with FIDO2
const { signedIn } = await authenticateWithFido2({
  username: "user@example.com",
});

// Wait for the sign-in process to complete
await signedIn;

// Sign-in with SRP **without MFA** (no rememberDevice callback needed)
const { signedIn } = await authenticateWithSRP({
  username: "user@example.com",
  password: "password123",
});

// If your user pool enforces an OTP second factor, provide the callback so it can
// ask the user after they enter the OTP:
const { signedIn: signedInWithOtp } = await authenticateWithSRP({
  username: "user@example.com",
  password: "password123",
  rememberDevice: async () => {
    return window.confirm("Remember this device?");
  },
});

// Sign out
await signOut();
```

### Usage in React

```jsx
import React, { useState, useEffect } from "react";
import {
  PasswordlessContextProvider,
  usePasswordless,
  useTotpMfa,
} from "@joinmeow/cognito-passwordless-auth/react";

function App() {
  return (
    <PasswordlessContextProvider enableLocalUserCache={true}>
      <YourApp />
    </PasswordlessContextProvider>
  );
}

function YourApp() {
  const {
    signInStatus,
    authenticateWithFido2,
    authenticateWithSRP,
    tokens,
    updateDeviceStatus,
  } = usePasswordless();
  const [showRememberDevice, setShowRememberDevice] = useState(false);

  // Check if we need to ask the user about remembering this device
  useEffect(() => {
    if (tokens?.userConfirmationNecessary) {
      setShowRememberDevice(true);
    }
  }, [tokens]);

  // Handle user's choice about remembering the device
  const handleRememberDevice = async (remember) => {
    if (tokens?.deviceKey && tokens?.accessToken) {
      await updateDeviceStatus({
        deviceKey: tokens.deviceKey,
        deviceRememberedStatus: remember ? "remembered" : "not_remembered",
      });
      setShowRememberDevice(false);
    }
  };

  // For TOTP MFA setup
  const { setupStatus, secretCode, qrCodeUrl, beginSetup, verifySetup } =
    useTotpMfa();

  if (signInStatus === "SIGNED_IN") {
    return (
      <div>
        <Dashboard />

        {/* Device remembering prompt */}
        {showRememberDevice && (
          <div className="remember-device-prompt">
            <p>
              Do you want to remember this device? You won't need MFA next time.
            </p>
            <button onClick={() => handleRememberDevice(true)}>
              Yes, remember
            </button>
            <button onClick={() => handleRememberDevice(false)}>
              No, don't remember
            </button>
          </div>
        )}
      </div>
    );
  }

  return (
    <div>
      <button onClick={() => authenticateWithFido2()}>
        Sign in with FIDO2
      </button>

      <form
        onSubmit={(e) => {
          e.preventDefault();
          const form = e.target;
          authenticateWithSRP({
            username: form.username.value,
            password: form.password.value,
            rememberDevice: async () => {
              return window.confirm("Remember this device?");
            },
          });
        }}
      >
        <input name="username" placeholder="Username" />
        <input name="password" type="password" placeholder="Password" />
        <button type="submit">Sign In</button>
      </form>
    </div>
  );
}
```

## Sign in with Google (OAuth2 Redirect)

When you call `signInWithGoogle()`, the library builds the Google OAuth2 authorization URL (including client ID, PKCE challenge, state, scopes, etc.) and redirects the browser. After the user signs in, Google redirects back to your registered `redirectUri` with `?code=...&state=...`.

On your callback page, call `handleGoogleCallback()` from `@joinmeow/cognito-passwordless-auth/client/google` to complete the flow:

Plain-JS / Multi-Page Example:

```html
<!-- /auth/google/callback.html -->
<script type="module">
  import { handleGoogleCallback } from "@joinmeow/cognito-passwordless-auth/client/google";
  (async () => {
    try {
      const tokens = await handleGoogleCallback();
      // Save tokens in your app (e.g. in memory or storage)
      window.location.href = "/";
    } catch (err) {
      console.error("Google OAuth failed", err);
      document.body.textContent = "Sign-in error: " + err.message;
    }
  })();
</script>
```

React Single-Page App Example:

```jsx
// GoogleCallback.jsx
import { useEffect } from "react";
import { useNavigate } from "react-router-dom";
import { handleGoogleCallback } from "@joinmeow/cognito-passwordless-auth/client/google";

export function GoogleCallback() {
  const navigate = useNavigate();

  useEffect(() => {
    (async () => {
      try {
        await handleGoogleCallback();
        navigate("/dashboard");
      } catch (err) {
        console.error("Google callback error", err);
        navigate("/login?error=oauth");
      }
    })();
  }, [navigate]);

  return <div>Signing you in…</div>;
}
```

Steps:

1. Configure Google OAuth in `Passwordless.configure({ google: { clientId, redirectUri, scopes } })`.
2. Initiate sign-in:

```js
import { signInWithGoogle } from "@joinmeow/cognito-passwordless-auth/client/google";
<button onClick={() => signInWithGoogle()}>Sign in with Google</button>;
```

3. After redirect, your callback page or component calls `handleGoogleCallback()` to exchange the code, store tokens, clean up the URL, and return the tokens.
4. Redirect users to your protected routes (e.g. `/dashboard`).

## Advanced Features

### User Registration Flow

The complete sign-up flow consists of:

```javascript
// 1. Register a new user
await signUp({
  username: "user@example.com",
  password: "securePassword123",
  userAttributes: [{ name: "email", value: "user@example.com" }],
});

// 2. If an error occurs during sign-up, you can resend the confirmation code
await resendConfirmationCode({ username: "user@example.com" });

// 3. Confirm the sign-up with the verification code that was sent to the user
await confirmSignUp({
  username: "user@example.com",
  confirmationCode: "123456", // Code received via email or SMS
});

// 4. After sign-up confirmation, the user can sign in
const { signedIn } = await authenticateWithSRP({
  username: "user@example.com",
  password: "securePassword123",
  rememberDevice: async () => {
    return window.confirm("Remember this device?");
  },
});
```

### Device Authentication Flow

Device authentication allows users to bypass MFA on subsequent sign-ins from the same device. The library handles most of this automatically:

```javascript
// 1. User signs in with SRP or another method
const { signedIn } = await authenticateWithSRP({
  username: "user@example.com",
  password: "securePassword123",
  rememberDevice: async () => {
    return window.confirm("Remember this device?");
  },
});

// 2. Wait for the sign-in to complete - including any "remember device" decisions
const tokens = await signedIn;

// 3. The signedIn promise won't resolve until:
// - User explicitly said "don't remember", or
// - The UpdateDeviceStatus call has completed, or
// - No rememberDevice callback was supplied
```

How device authentication works:

1. **Device Confirmation** (automatic): When a user signs in with MFA on a new device, the library automatically registers the device with Cognito.

2. **Device Remembering** (user choice): When `userConfirmationNecessary` is true, your app's `rememberDevice` callback is invoked, giving you control over when and how to ask the user.

3. **Atomic Authentication Flow**: The `signedIn` promise doesn't resolve until the entire flow (including device status updates) is complete.

4. **Subsequent Sign-ins**: On remembered devices, users bypass MFA automatically.

Important: The `rememberDevice` callback is **only invoked after successful MFA authentication** (like TOTP or SMS). For users without MFA enabled, or for sign-ins that don't trigger an MFA step, the callback will never be invoked and device remembering is not possible.

### TOTP MFA Setup

Set up Time-Based One-Time Password MFA for a user:

```javascript
// Configure the TOTP issuer (defaults to "YourApp")
configure({
  // ... other configuration
  totp: {
    issuer: "YourCompany", // The name shown in authenticator apps
  },
});

// In a React component
const { setupStatus, secretCode, qrCodeUrl, beginSetup, verifySetup } =
  useTotpMfa();

// Start setup
await beginSetup();

// Show QR code to user (qrCodeUrl contains the otpauth:// URL)
// The QR code will show "YourCompany:username" in authenticator apps
// ...

// Verify the code from the user's authenticator app
await verifySetup(userEnteredCode, "My Authenticator");
```

> **Note:** TOTP MFA setup requires proper configuration. The `issuer` setting controls what name appears in authenticator apps like Google Authenticator or Authy.

### Device Management

The library provides comprehensive device management capabilities for trusted device authentication:

#### React Hook Usage

```jsx
import React, { useState } from "react";
import { usePasswordless } from "@joinmeow/cognito-passwordless-auth/react";

function DeviceManager() {
  const {
    deviceKey,
    confirmDevice,
    updateDeviceStatus,
    forgetDevice,
    clearDeviceKey,
    tokens,
  } = usePasswordless();
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const handleConfirmDevice = async () => {
    if (!deviceKey) return;

    try {
      setLoading(true);
      setError(null);
      await confirmDevice("My Laptop");
      console.log("Device confirmed successfully");
    } catch (error) {
      console.error("Failed to confirm device:", error);
      setError(error.message);
    } finally {
      setLoading(false);
    }
  };

  const handleRememberDevice = async (remember: boolean) => {
    if (!deviceKey) return;

    try {
      setLoading(true);
      setError(null);
      await updateDeviceStatus({
        deviceKey,
        deviceRememberedStatus: remember ? "remembered" : "not_remembered",
      });
    } catch (error) {
      console.error("Failed to update device status:", error);
      setError(error.message);
    } finally {
      setLoading(false);
    }
  };

  const handleForgetDevice = async () => {
    try {
      setLoading(true);
      setError(null);
      await forgetDevice(); // Forgets current device
      // Or forget a specific device: await forgetDevice(specificDeviceKey);
    } catch (error) {
      console.error("Failed to forget device:", error);
      setError(error.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div>
      {error && <div style={{color: 'red'}}>Error: {error}</div>}

      {deviceKey && (
        <div>
          <p>Device Key: {deviceKey}</p>
          <button onClick={handleConfirmDevice} disabled={loading}>
            {loading ? "Confirming..." : "Confirm This Device"}
          </button>
          <button onClick={() => handleRememberDevice(true)} disabled={loading}>
            Remember This Device
          </button>
          <button onClick={() => handleRememberDevice(false)} disabled={loading}>
            Don't Remember This Device
          </button>
          <button onClick={handleForgetDevice} disabled={loading}>
            {loading ? "Forgetting..." : "Forget This Device"}
          </button>
          <button onClick={clearDeviceKey}>Clear Local Device Key</button>
        </div>
      )}
    </div>
  );
}
```

#### Device Management Flow

```javascript
// 1. After successful authentication with MFA, a device key is available
const { signedIn } = await authenticateWithSRP({
  username: "user@example.com",
  password: "password123",
  rememberDevice: async () => {
    // This callback is called when userConfirmationNecessary is true
    return window.confirm("Remember this device for future sign-ins?");
  },
});

// 2. The device is automatically confirmed and optionally remembered
const tokens = await signedIn;

// 3. Manually manage device status later
if (tokens.deviceKey) {
  // Update device status
  await updateDeviceStatus({
    deviceKey: tokens.deviceKey,
    deviceRememberedStatus: "remembered",
  });

  // Or forget the device entirely
  await forgetDevice(tokens.deviceKey);
}
```

### FIDO2 Credential Management

Manage WebAuthn/FIDO2 credentials for passwordless authentication:

#### React Hook Usage

```jsx
import React, { useState } from "react";
import { usePasswordless } from "@joinmeow/cognito-passwordless-auth/react";

function FIDO2Manager() {
  const {
    fido2Credentials,
    creatingCredential,
    fido2CreateCredential,
    userVerifyingPlatformAuthenticatorAvailable,
  } = usePasswordless();
  const [error, setError] = useState(null);

  const handleCreateCredential = async () => {
    try {
      setError(null);
      await fido2CreateCredential({
        friendlyName: "My Face ID",
      });
      console.log("FIDO2 credential created successfully");
    } catch (error) {
      console.error("Failed to create FIDO2 credential:", error);
      setError(error.message);
    }
  };

  const handleUpdateCredential = async (credential, newName) => {
    try {
      setError(null);
      await credential.update({ friendlyName: newName });
      console.log("Credential updated successfully");
    } catch (error) {
      console.error("Failed to update credential:", error);
      setError(error.message);
    }
  };

  const handleDeleteCredential = async (credential) => {
    if (!window.confirm("Are you sure you want to delete this credential?")) {
      return;
    }

    try {
      setError(null);
      await credential.delete();
      console.log("Credential deleted successfully");
    } catch (error) {
      console.error("Failed to delete credential:", error);
      setError(error.message);
    }
  };

  return (
    <div>
      <h3>FIDO2 Credentials</h3>

      {error && <div style={{ color: "red" }}>Error: {error}</div>}

      {userVerifyingPlatformAuthenticatorAvailable && (
        <button onClick={handleCreateCredential} disabled={creatingCredential}>
          {creatingCredential ? "Creating..." : "Add New Credential"}
        </button>
      )}

      {fido2Credentials?.map((credential) => (
        <div
          key={credential.credentialId}
          style={{ border: "1px solid #ccc", margin: "10px", padding: "10px" }}
        >
          <h4>{credential.friendlyName || "Unnamed Credential"}</h4>
          <p>Created: {new Date(credential.createdAt).toLocaleDateString()}</p>
          <p>
            Last Used: {new Date(credential.lastUseDate).toLocaleDateString()}
          </p>

          <button
            onClick={() => {
              const newName = prompt(
                "Enter new name:",
                credential.friendlyName
              );
              if (newName) handleUpdateCredential(credential, newName);
            }}
            disabled={credential.busy}
          >
            {credential.busy ? "Updating..." : "Update Name"}
          </button>

          <button
            onClick={() => handleDeleteCredential(credential)}
            disabled={credential.busy}
            style={{
              marginLeft: "10px",
              backgroundColor: "#ff4444",
              color: "white",
            }}
          >
            {credential.busy ? "Deleting..." : "Delete"}
          </button>
        </div>
      ))}

      {fido2Credentials?.length === 0 && (
        <p>No FIDO2 credentials registered.</p>
      )}
    </div>
  );
}
```

#### FIDO2 Authentication Flow

```javascript
// 1. Check if platform authenticator is available
if (userVerifyingPlatformAuthenticatorAvailable) {
  // 2. Create a new credential
  await fido2CreateCredential({
    friendlyName: "iPhone Face ID",
  });

  // 3. Sign in with FIDO2
  const { signedIn } = await authenticateWithFido2({
    username: "user@example.com",
    // Optional: specify credentials to use
    credentials: fido2Credentials?.map((c) => ({
      id: c.credentialId,
      transports: c.transports,
    })),
  });

  await signedIn;
}
```

### Local User Cache Management

The `useLocalUserCache()` hook manages a cache of recently signed-in users for improved UX:

#### Setup and Usage

```jsx
import React, { useCallback } from "react";
import {
  PasswordlessContextProvider,
  usePasswordless,
  useLocalUserCache,
} from "@joinmeow/cognito-passwordless-auth/react";

// 1. Enable local user cache in the provider
function App() {
  return (
    <PasswordlessContextProvider enableLocalUserCache={true}>
      <YourApp />
    </PasswordlessContextProvider>
  );
}

// 2. Use the cache in your components
function UserSelector() {
  const {
    currentUser,
    lastSignedInUsers,
    clearLastSignedInUsers,
    updateFidoPreference,
    signingInStatus,
    authMethod,
  } = useLocalUserCache();

  const { authenticateWithFido2, authenticateWithSRP } = usePasswordless();

  const handleQuickSignIn = useCallback(
    async (user) => {
      try {
        if (user.useFido === "YES" && user.credentials) {
          // Sign in with FIDO2 using stored credentials
          await authenticateWithFido2({
            username: user.username,
            credentials: user.credentials,
          });
        } else {
          // Fall back to password authentication
          const password = prompt("Enter your password:");
          if (password) {
            await authenticateWithSRP({
              username: user.username,
              password,
            });
          }
        }
      } catch (error) {
        console.error("Quick sign-in failed:", error);
        alert("Sign-in failed: " + error.message);
      }
    },
    [authenticateWithFido2, authenticateWithSRP]
  );

  const handleFidoPreferenceChange = useCallback(
    (useFido) => {
      updateFidoPreference({ useFido });
    },
    [updateFidoPreference]
  );

  return (
    <div>
      <h3>Recent Users</h3>

      {currentUser && (
        <div
          style={{ border: "1px solid #ccc", padding: "10px", margin: "10px" }}
        >
          <h4>Current User: {currentUser.username}</h4>
          <p>Email: {currentUser.email}</p>
          <p>Auth Method: {currentUser.authMethod}</p>
          <p>FIDO2 Preference: {currentUser.useFido}</p>

          <button onClick={() => handleFidoPreferenceChange("YES")}>
            Enable FIDO2
          </button>
          <button onClick={() => handleFidoPreferenceChange("NO")}>
            Disable FIDO2
          </button>
        </div>
      )}

      <h4>Quick Sign-In</h4>
      {lastSignedInUsers?.map((user) => (
        <div key={user.username} style={{ margin: "5px 0" }}>
          <button
            onClick={() => handleQuickSignIn(user)}
            disabled={signingInStatus !== "SIGNED_OUT"}
          >
            {user.email || user.username}
            {user.useFido === "YES" && " (FIDO2)"}
          </button>
        </div>
      ))}

      <button onClick={clearLastSignedInUsers} style={{ marginTop: "10px" }}>
        Clear User History
      </button>

      {signingInStatus !== "SIGNED_OUT" && <p>Status: {signingInStatus}</p>}
    </div>
  );
}
```

#### StoredUser Object Structure

```typescript
type StoredUser = {
  username: string;
  email?: string;
  useFido?: "YES" | "NO" | "ASK";
  credentials?: { id: string; transports?: AuthenticatorTransport[] }[];
  authMethod?: "SRP" | "FIDO2" | "PLAINTEXT" | "REDIRECT";
};
```

### Utility Hooks

#### useAwaitableState

Convert any state value into a promise that can be awaited:

```jsx
import React, { useState } from "react";
import { useAwaitableState } from "@joinmeow/cognito-passwordless-auth/react";

function AsyncStateExample() {
  const [data, setData] = useState(null);
  const awaitableData = useAwaitableState(data);
  const [waiting, setWaiting] = useState(false);

  const handleWaitForData = async () => {
    try {
      setWaiting(true);
      console.log("Waiting for data...");

      // This will wait until data is set to a truthy value
      const result = await awaitableData.awaitable();
      console.log("Data received:", result);
    } catch (error) {
      console.error("Waiting failed:", error);
    } finally {
      setWaiting(false);
    }
  };

  const handleSetData = () => {
    setData("Hello World");
    // Resolve the awaitable with the current data value
    awaitableData.resolve();
  };

  const handleRejectData = () => {
    awaitableData.reject(new Error("Data loading failed"));
  };

  return (
    <div>
      <p>Current data: {data}</p>
      <p>Awaited data: {awaitableData.awaited?.value}</p>

      <button onClick={handleWaitForData} disabled={waiting}>
        {waiting ? "Waiting..." : "Wait for Data"}
      </button>
      <button onClick={handleSetData}>Set Data</button>
      <button onClick={handleRejectData}>Reject</button>
    </div>
  );
}
```

## API Reference

### usePasswordless() Hook

Complete reference of all available properties and methods:

#### State Properties

```typescript
// Token and authentication state
tokens?: TokensFromStorage               // Raw JWT tokens
tokensParsed?: {                        // Parsed token contents
  idToken: CognitoIdTokenPayload;
  accessToken: CognitoAccessTokenPayload;
  expireAt: Date;
}
signInStatus: string                    // Overall auth status
signingInStatus: BusyState | IdleState  // Current operation status
busy: boolean                          // Is any auth operation in progress
lastError?: Error                      // Last error that occurred
authMethod?: string                    // Current auth method used

// Token refresh state
isRefreshingTokens: boolean            // Is token refresh in progress

// FIDO2 state
userVerifyingPlatformAuthenticatorAvailable?: boolean  // Platform auth available
fido2Credentials?: Fido2Credential[]   // User's FIDO2 credentials
creatingCredential: boolean            // Is creating FIDO2 credential

// Device management
deviceKey: string | null               // Current device key

// TOTP MFA state
totpMfaStatus: {
  enabled: boolean;
  preferred: boolean;
  availableMfaTypes: string[];
}

// Activity tracking (when enabled)
timeSinceLastActivityMs: number | null     // Milliseconds since last activity
timeSinceLastActivitySeconds: number | null // Seconds since last activity
```

#### Methods

```typescript
// Authentication methods
authenticateWithFido2(options?: {
  username?: string;
  credentials?: { id: string; transports?: AuthenticatorTransport[] }[];
  clientMetadata?: Record<string, string>;
}) => { signedIn: Promise<TokensFromSignIn> }

authenticateWithSRP(options: {
  username: string;
  password: string;
  smsMfaCode?: () => Promise<string>;
  otpMfaCode?: () => Promise<string>;
  newPassword?: () => Promise<string>;
  clientMetadata?: Record<string, string>;
  rememberDevice?: () => Promise<boolean>;
}) => { signedIn: Promise<TokensFromSignIn> }

authenticateWithPlaintextPassword(options: {
  username: string;
  password: string;
  smsMfaCode?: () => Promise<string>;
  otpMfaCode?: () => Promise<string>;
  clientMetadata?: Record<string, string>;
  rememberDevice?: () => Promise<boolean>;
}) => { signedIn: Promise<TokensFromSignIn> }

signInWithRedirect(options?: {
  provider?: string;
  customState?: string;
}) => void

signOut(options?: {
  skipTokenRevocation?: boolean
}) => { signedOut: Promise<void> }

// Token management
refreshTokens(abort?: AbortSignal) => Promise<void>
forceRefreshTokens(abort?: AbortSignal) => Promise<void>
markUserActive() => void  // Mark user as active for activity tracking

// Device management
confirmDevice(deviceName: string) => Promise<any>
updateDeviceStatus(options: {
  deviceKey: string;
  deviceRememberedStatus: "remembered" | "not_remembered";
}) => Promise<void>
forgetDevice(deviceKeyToForget?: string) => Promise<void>
clearDeviceKey() => void

// FIDO2 credential management
fido2CreateCredential(options: {
  friendlyName: string | (() => string | Promise<string>);
}) => Promise<StoredCredential>

// TOTP MFA
refreshTotpMfaStatus() => Promise<void>
```

> **Note:** Activity tracking features require enabling in your configuration:
>
> ```javascript
> Passwordless.configure({
>   // ... other configuration
>   tokenRefresh: {
>     useActivityTracking: true,
>   },
> });
> ```

### useLocalUserCache() Hook

```typescript
// Properties
currentUser?: StoredUser               // Currently signed-in user
lastSignedInUsers?: StoredUser[]       // Last 10 signed-in users
signingInStatus: BusyState | IdleState // Current signing status
authMethod?: string                    // Current auth method

// Methods
updateFidoPreference(options: {
  useFido: "YES" | "NO"
}) => void
clearLastSignedInUsers() => void
```

### useTotpMfa() Hook

```typescript
// Properties
setupStatus: "IDLE" | "GENERATING" | "READY" | "VERIFYING" | "VERIFIED" | "ERROR"
secretCode?: string                    // Secret for QR code
qrCodeUrl?: string                     // QR code URL
errorMessage?: string                  // Setup error message
totpMfaStatus: {                      // Current MFA status
  enabled: boolean;
  preferred: boolean;
  availableMfaTypes: string[];
}

// Methods
beginSetup() => Promise<{ SecretCode: string }>
verifySetup(code: string, deviceName?: string) => Promise<{ Status: string }>
resetSetup() => void
```

### useAwaitableState(state) Hook

```typescript
// Methods
awaitable() => Promise<T>              // Get current promise
resolve() => void                      // Resolve with current state
reject(reason: Error) => void          // Reject the promise

// Properties
awaited?: { value: T }                 // Resolved value (if any)
```

## Library Architecture

The library is organized into several modules that handle different aspects of authentication:

- **Core Configuration**: `config.ts` - Central configuration for the library
- **Authentication APIs**:
  - `cognito-api.ts` - Direct interactions with Cognito Identity Provider API
  - `srp.ts` - Secure Remote Password implementation
  - `fido2.ts` - WebAuthn/FIDO2 authentication
  - `plaintext.ts` - Basic password authentication
  - `device.ts` - Device remembering and authentication
- **Token Management**:
  - `storage.ts` - Token persistence and retrieval
  - `refresh.ts` - Token refresh scheduling and automatic renewal

## License and Attribution

Apache-2.0 © Amazon.com, Inc. and its affiliates.

This is a fork by Meow Technologies Inc. (https://meow.com), based on the original work by Amazon. All modifications are also licensed under Apache-2.0.
