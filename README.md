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
import { Passwordless, initialize, signUp, confirmSignUp } from "@joinmeow/cognito-passwordless-auth";

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
    { name: "name", value: "Jane Doe" }
  ]
});

// Confirm sign up with verification code
await confirmSignUp({
  username: "user@example.com",
  confirmationCode: "123456"
});

// Start the sign-in process with FIDO2
const { signedIn } = await authenticateWithFido2({ 
  username: "user@example.com" 
});

// Wait for the sign-in process to complete
await signedIn;

// Sign in with password (SRP)
const { signedIn } = await authenticateWithSRP({
  username: "user@example.com",
  password: "password123",
  // Use device authentication if available
  deviceKey: localStorage.getItem("deviceKey")
});

// Sign out
await signOut();
```

### Usage in React

```jsx
import {
  PasswordlessContextProvider,
  usePasswordless,
  useTotpMfa
} from "@joinmeow/cognito-passwordless-auth/react";

function App() {
  return (
    <PasswordlessContextProvider
      enableLocalUserCache={true}
    >
      <YourApp />
    </PasswordlessContextProvider>
  );
}

function YourApp() {
  const { 
    signInStatus, 
    authenticateWithFido2, 
    authenticateWithSRP,
    deviceKey,
    confirmDevice,
    forgetDevice 
  } = usePasswordless();

  // For TOTP MFA setup
  const { 
    setupStatus, 
    secretCode, 
    qrCodeUrl, 
    beginSetup, 
    verifySetup 
  } = useTotpMfa();

  if (signInStatus === "SIGNED_IN") {
    return <Dashboard />;
  }

  return (
    <div>
      <button onClick={() => authenticateWithFido2()}>
        Sign in with FIDO2
      </button>
      
      <form onSubmit={(e) => {
        e.preventDefault();
        const form = e.target;
        authenticateWithSRP({
          username: form.username.value,
          password: form.password.value,
          // Use saved device key for faster authentication
          deviceKey
        });
      }}>
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
  userAttributes: [
    { name: "email", value: "user@example.com" }
  ]
});

// 2. If an error occurs during sign-up, you can resend the confirmation code
await resendConfirmationCode({ username: "user@example.com" });

// 3. Confirm the sign-up with the verification code that was sent to the user
await confirmSignUp({
  username: "user@example.com",
  confirmationCode: "123456"  // Code received via email or SMS
});

// 4. After sign-up confirmation, the user can sign in
const { signedIn } = await authenticateWithSRP({
  username: "user@example.com",
  password: "securePassword123"
});
```

### Device Authentication Flow

The device authentication flow eliminates the need for MFA on subsequent sign-ins from the same device:

```javascript
// 1. User signs in with SRP or plaintext password
const { signedIn } = await authenticateWithSRP({
  username: "user@example.com",
  password: "securePassword123"
});

// 2. Wait for the sign-in to complete
const tokens = await signedIn;

// 3. If the sign-in response includes new device metadata, register the device
if (tokens.newDeviceMetadata?.deviceKey) {
  // Store device key for future authentications
  localStorage.setItem("deviceKey", tokens.newDeviceMetadata.deviceKey);
  
  // Generate SRP salt and verifier for the device
  const deviceVerifierConfig = generateDeviceVerifier();
  
  // 4. Confirm the device with server
  const result = await confirmDevice(
    "My Device", 
    deviceVerifierConfig
  );
  
  // 5. If user confirmation is required, mark as remembered (this step is handled by the library)
  if (result.UserConfirmationNecessary) {
    await updateDeviceStatus({
      deviceKey: tokens.newDeviceMetadata.deviceKey,
      deviceRememberedStatus: "remembered"
    });
  }
}

// 6. On subsequent sign-ins, include the device key
const { signedIn } = await authenticateWithSRP({
  username: "user@example.com",
  password: "securePassword123",
  deviceKey: localStorage.getItem("deviceKey")
});

// 7. When using a remembered device, Cognito will send DEVICE_SRP_AUTH challenge
// instead of MFA challenge, which the library handles automatically
```

When a user signs in with a remembered device:
1. The library includes the device key in the authentication request
2. Amazon Cognito sends a DEVICE_SRP_AUTH challenge instead of an MFA challenge
3. The library automatically responds to the device challenge
4. The user is signed in without needing to provide an additional MFA code

### TOTP MFA Setup

Set up Time-Based One-Time Password MFA for a user:

```javascript
// In a React component
const { 
  setupStatus, 
  secretCode, 
  qrCodeUrl, 
  beginSetup, 
  verifySetup 
} = useTotpMfa();

// Start setup
await beginSetup();

// Show QR code to user (qrCodeUrl contains the otpauth:// URL)
// ...

// Verify the code from the user's authenticator app
await verifySetup(userEnteredCode, "My Authenticator");
```

## Password Reset Flow

The library also supports password reset functionality:

```javascript
// 1. Request a password reset code
await forgotPassword({
  username: "user@example.com"
});

// 2. Complete the password reset with the code received via email/SMS
await confirmForgotPassword({
  username: "user@example.com",
  confirmationCode: "123456",
  password: "newSecurePassword123"
});

// 3. User can now sign in with the new password
```

## Documentation

For more detailed documentation about the available API methods and components, check the client source code.

## License

Apache-2.0
