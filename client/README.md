# Usage in (plain) Web

### Configuration

To use the library, you need to first configure it:

```javascript
import { configure } from "@joinmeow/cognito-passwordless-auth";

configure({
  cognitoIdpEndpoint: "us-east-2", // you can also use the full endpoint URL, potentially to use a proxy
  clientId: "<client id>",
  // optional, only required if you want to use FIDO2:
  fido2: {
    baseUrl: "<fido2 base url>",
    /**
     * all other FIDO2 config is optional, values below are examples only to illustrate what you might configure.
     * (this client side config is essentially an override, that's merged on top of the config received from the backend)
     */
    authenticatorSelection: {
      userVerification: "required",
      requireResidentKey: true,
      residentKey: "preferred",
      authenticatorAttachment: "platform",
    },
    rp: {
      id: "example.com",
      name: "Example",
    },
    attestation: "direct",
    extensions: {
      appid: "u2f.example.com",
      credProps: true,
      hmacCreateSecret: true,
    },
    timeout: 120000,
  },
  userPoolId: "<user pool id>", // optional, only required if you want to use USER_SRP_AUTH
  // optional, additional headers that will be sent with each request to Cognito:
  proxyApiHeaders: {
    "<header 1>": "<value 1>",
    "<header 2>": "<value 2>",
  },
  storage: localStorage, // Optional, defaults to localStorage
  // Whether to use the new GetTokensFromRefreshToken API
  useGetTokensFromRefreshToken: true, // Default is true
});
```

### Sign Up

If your User Pool is enabled for self sign-up, users can sign up like so:

```javascript
import { signUp } from "@joinmeow/cognito-passwordless-auth/cognito-api";

export default function YourComponent() {
  // Sample form that allows the user to sign up
  return (
    <form
      onSubmit={(event) => {
        signUp({
          username: event.currentTarget.username.value,
          password: event.currentTarget.password.value,
          // userAttributes are optional and you can pass any Cognito User pool attributes
          // Read more: https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-settings-attributes.html
          userAttributes: [
            {
              name: "name",
              value: event.currentTarget.name.value,
            },
          ],
        });
        event.preventDefault();
      }}
    >
      <input type="text" placeholder="Username" name="username" />
      <input type="password" placeholder="Password" name="password" />
      <input type="text" placeholder="Your name" name="name" />
      <input type="submit" value="Sign up" />
    </form>
  );
}
```

### Update Cognito User Attributes

To update your Cognito User Attributes you can use the `updateUserAttributes` function:

```javascript
import { updateUserAttributes } from "@joinmeow/cognito-passwordless-auth/cognito-api";

await updateUserAttributes({
  userAttributes: [
    {
      name: "name",
      value: "YOUR NEW NAME",
    },
  ],
});
```

### Send the user attribute verification code

To receive a code via email or SMS to verify the `email` or `phone_number` respectively, use the `getUserAttributeVerificationCode` function:

```javascript
import { getUserAttributeVerificationCode } from "@joinmeow/cognito-passwordless-auth/cognito-api";

await getUserAttributeVerificationCode({
  attributeName: "email",
});
await getUserAttributeVerificationCode({
  attributeName: "phone_number",
});
```

### Verify Cognito User Attribute

To verify `email` or `phone_number` attributes, use the `verifyUserAttribute` function

```javascript
import { verifyUserAttribute } from "@joinmeow/cognito-passwordless-auth/cognito-api";

await verifyUserAttribute({
  attributeName: "phone_number",
  code: "123456",
});
```

### Helpers

**timeAgo(now: number, from: Date)**

A helper function that returns a human friendly string indicating how much time passed from the `from` Date to the `now` timestamp

```javascript
import { timeAgo } from "@joinmeow/cognito-passwordless-auth/util";

const now = timeAgo(Date.now(), new Date()); // Just now
const seconds = timeAgo(Date.now(), new Date(Date.now() - 30 * 1000)); // 30 seconds ago
const hours = timeAgo(Date.now(), new Date(Date.now() - 2 * 3600 * 1000)); // 2 hours ago
```

## Refresh Token Rotation

This library supports the new GetTokensFromRefreshToken API that was introduced by AWS Cognito. This API supports refresh token rotation, which enhances security by automatically invalidating used refresh tokens after a grace period when enabled in your user pool.

### GetTokensFromRefreshToken API (Default)

This library uses the GetTokensFromRefreshToken API by default. This API supports refresh token rotation, which enhances security by automatically invalidating used refresh tokens after a grace period when enabled in your user pool.

If you need to use the legacy InitiateAuth approach instead, you can disable this feature:

```typescript
import { configure } from "@joinmeow/cognito-passwordless-auth";

configure({
  // ...your other configuration options
  useGetTokensFromRefreshToken: false, // Override the default (true)
});
```

By default (enabled):

- The library uses the GetTokensFromRefreshToken API instead of InitiateAuth with REFRESH_TOKEN flow
- Any new refresh tokens returned as part of token refresh (when refresh token rotation is enabled in your user pool) will be automatically stored and used for future refresh operations
- Debug logs will show when refresh token rotation occurs

When explicitly disabled:

- The library will use the older InitiateAuth API with REFRESH_TOKEN flow

### Configuring Refresh Token Rotation in Your User Pool

To enable refresh token rotation in your Cognito User Pool client:

1. Go to the AWS Console and navigate to Amazon Cognito > User Pools > [Your User Pool] > App integration > App clients and analytics
2. Select the app client you want to modify
3. Under "Refresh token expiration", set the desired rotation type and token validity period
4. Set an appropriate grace period for token reuse during which both the old and new refresh tokens will be valid

For more information, see the [AWS documentation on RefreshTokenRotationType](https://docs.aws.amazon.com/cognito-idp/latest/APIReference/API_GetTokensFromRefreshToken.html).

## Device Authentication

When a user signs in for the first time on a new device, this library automatically handles device authentication with Amazon Cognito, allowing users to bypass MFA on subsequent sign-ins from remembered devices.

### How Device Authentication Works

The device authentication flow has two distinct steps:

1. **Device Confirmation** (automatic): When a user signs in with MFA on a new device, the library:

   - Detects the `NewDeviceMetadata` from Cognito
   - Automatically registers the device with Cognito using the `ConfirmDevice` API
   - Returns a `userConfirmationNecessary` flag to indicate if user input is needed

   Important: Device confirmation only happens when MFA is used during authentication. This ensures that device authentication maintains proper security by only allowing devices to be remembered after the user has successfully completed an MFA challenge.

2. **Device Remembering** (requires user consent): Based on your User Pool settings, the user may need to be asked if they want to remember the device.
   - If `userConfirmationNecessary` is `true`, your application should ask the user
   - Based on the user's choice, your application calls `updateDeviceStatus`

Here's a diagram of the flow:

```
┌─────────────┐       ┌─────────────┐       ┌─────────────┐
│  User signs │       │   Library   │       │ Application │
│  in with MFA│──────▶│  confirms   │──────▶│ asks user to│
│             │       │   device    │       │ remember?   │
└─────────────┘       └─────────────┘       └──────┬──────┘
                                                   │
                                                   ▼
                                            ┌─────────────┐
                                            │  Update     │
                                            │  device     │
                                            │  status     │
                                            └─────────────┘
```

### Implementation Example

```javascript
// Web example:
import {
  authenticateWithSRP,
  updateDeviceStatus,
} from "@joinmeow/cognito-passwordless-auth";

// Sign in with username and password
const { signedIn } = await authenticateWithSRP({
  username: "user@example.com",
  password: "securePassword123",
  rememberDevice: async () => {
    return window.confirm("Remember this device?");
  },
});

// Wait for sign-in to complete and get tokens
// This will only resolve AFTER any "remember device" process completes
const tokens = await signedIn;

// The rememberDevice callback is only invoked when MFA is used and
// Cognito indicates userConfirmationNecessary = true
// IMPORTANT: Device remembering ONLY works after successful TOTP or SMS MFA authentication.
// Without an MFA step, the rememberDevice callback will never be invoked.
// When this happens, signedIn won't resolve until either:
// 1. The callback resolves to false (don't remember)
// 2. The callback resolves to true AND updateDeviceStatus completes
```
