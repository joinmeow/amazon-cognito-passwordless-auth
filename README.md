# Amazon Cognito Passwordless Auth (Client)

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

// Sign in with password (SRP)
const { signedIn } = await authenticateWithSRP({
  username: "user@example.com",
  password: "password123",
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
});
```

### Device Authentication Flow

Device authentication allows users to bypass MFA on subsequent sign-ins from the same device. The library handles most of this automatically:

```javascript
// 1. User signs in with SRP or another method
const { signedIn } = await authenticateWithSRP({
  username: "user@example.com",
  password: "securePassword123",
});

// 2. Wait for the sign-in to complete
const tokens = await signedIn;

// 3. Check if the user needs to be asked about remembering the device
if (tokens.userConfirmationNecessary) {
  // Ask the user if they want to remember this device
  const rememberDevice = confirm(
    "Remember this device? You won't need MFA next time."
  );

  // Update device status based on user's choice
  await updateDeviceStatus({
    accessToken: tokens.accessToken,
    deviceKey: tokens.deviceKey,
    deviceRememberedStatus: rememberDevice ? "remembered" : "not_remembered",
  });
}

// 4. On subsequent sign-ins, the library automatically uses the remembered device
// and handles the DEVICE_SRP_AUTH challenge instead of requiring MFA
```

How device authentication works:

1. **Device Confirmation** (automatic): When a user signs in with MFA on a new device, the library automatically registers the device with Cognito.

2. **Device Remembering** (user choice): Your app should ask users if they want to remember the device when `tokens.userConfirmationNecessary` is true.

3. **Subsequent Sign-ins**: On remembered devices, users bypass MFA automatically.

Important: Device confirmation now only happens when MFA is used during authentication. This ensures that device authentication maintains proper security by only allowing devices to be remembered after the user has successfully completed an MFA challenge.

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

## Password Reset Flow

The library also supports password reset functionality:

```javascript
// 1. Request a password reset code
await forgotPassword({
  username: "user@example.com",
});

// 2. Complete the password reset with the code received via email/SMS
await confirmForgotPassword({
  username: "user@example.com",
  confirmationCode: "123456",
  password: "newSecurePassword123",
});

// 3. User can now sign in with the new password
```

## Configuration

Configure the following properties:

```typescript
import { configure } from "@joinmeow/cognito-passwordless-auth";

configure({
  clientId: "...",
  cognitoIdpEndpoint: "...",
  // ... other config properties

  // Whether to use the new GetTokensFromRefreshToken API instead of InitiateAuth with REFRESH_TOKEN.
  // When true, uses the new API. When false (default), uses the legacy approach.
  useGetTokensFromRefreshToken: false, // (default: false)
});
```

## Documentation

For more detailed documentation about the available API methods and components, check the client source code.

## License

Apache-2.0
