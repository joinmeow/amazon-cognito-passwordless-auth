# Amazon Cognito Passwordless Auth (Client)

A client-side library for implementing passwordless authentication with Amazon Cognito. This package provides the frontend implementation for various passwordless authentication methods:

- **FIDO2**: aka **WebAuthn**, i.e. sign in with Face, Touch, YubiKey, etc. This includes support for **Passkeys** (i.e. usernameless authentication).
- **Magic Link Sign In**: sign in with a one-time-use secret link that's emailed to you (and works across browsers).

This is a client-only version of the [original Amazon Cognito Passwordless Auth solution](https://github.com/aws-samples/amazon-cognito-passwordless-auth), intended for use with an already configured backend.

## Installation

```shell
npm install @joinmeow/amazon-cognito-passwordless-auth
```

## Usage

This library provides implementations for different frontend frameworks:

### Usage in (plain) Web

```javascript
import { Passwordless } from "@joinmeow/amazon-cognito-passwordless-auth";

// Configure the client
Passwordless.configure({
  userPoolId: "us-east-1_example",
  clientId: "abcdefghijklmnopqrstuvwxyz",
  // Other configuration parameters as needed
});

// Start the sign-in process
await Passwordless.signInWithFido2();
// or
await Passwordless.signInWithMagicLink("user@example.com");
```

### Usage in React

```jsx
import { PasswordlessProvider, usePasswordless } from "@joinmeow/amazon-cognito-passwordless-auth/react";

function App() {
  return (
    <PasswordlessProvider
      userPoolId="us-east-1_example"
      clientId="abcdefghijklmnopqrstuvwxyz"
    >
      <YourApp />
    </PasswordlessProvider>
  );
}

function YourApp() {
  const { signInWithFido2, signInWithMagicLink } = usePasswordless();
  
  return (
    <div>
      <button onClick={() => signInWithFido2()}>Sign in with FIDO2</button>
      <button onClick={() => signInWithMagicLink("user@example.com")}>
        Sign in with Magic Link
      </button>
    </div>
  );
}
```

## Documentation

For more detailed documentation about the available API methods and components, check the client source code.

## License

Apache-2.0
