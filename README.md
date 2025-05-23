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
        accessToken: tokens.accessToken,
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
  - `refresh.ts`

## License and Attribution

Apache-2.0 © Amazon.com, Inc. and its affiliates.

This is a fork by Meow Technologies Inc. (https://meow.com), based on the original work by Amazon. All modifications are also licensed under Apache-2.0.
