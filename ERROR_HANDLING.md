# Error Handling Guide

## Custom Error Classes

The library provides typed error classes with **dual messaging** for optimal developer and user experience:

- **`message`** - Technical details for developers and logging
- **`userMessage`** - User-friendly passkey language for UI display

### Error Hierarchy

```typescript
Fido2Error (base class)
├── Fido2AbortError          - Passkey verification cancelled
├── Fido2CredentialError     - Passkey operations failed
├── Fido2ConfigError         - Passkeys not properly configured
├── Fido2ValidationError     - Passkey validation failed
├── Fido2AuthError          - Passkey authentication failed
└── Fido2NetworkError       - Passkey service connection failed
```

## Usage Examples

### Basic Error Handling with User-Friendly Messages

```typescript
import {
  authenticateWithFido2,
  Fido2AbortError,
  Fido2CredentialError,
  Fido2ConfigError,
  isFido2Error,
} from "@joinmeow/cognito-passwordless-auth";

try {
  const { signedIn } = authenticateWithFido2({ username: "user@example.com" });
  const tokens = await signedIn;

  // Success!
  console.log("Signed in:", tokens);
} catch (error) {
  if (error instanceof Fido2AbortError) {
    // User cancelled the passkey prompt - don't show error
    console.log("User cancelled authentication");
    return;
  }

  if (error instanceof Fido2CredentialError) {
    // Show user-friendly message
    console.error(error.message); // Technical: for logs
    setError(error.userMessage); // User-friendly: "Unable to complete passkey operation"
    return;
  }

  if (error instanceof Fido2ConfigError) {
    // Developer error - WebAuthn not configured
    console.error(error.message); // Technical details
    setError(error.userMessage); // User-friendly: "Passkeys are not properly configured"
    return;
  }

  // Generic handler for all Fido2 errors
  if (isFido2Error(error)) {
    console.error(error.message);
    setError(error.userMessage); // Always user-friendly!
    return;
  }

  // Unknown error
  console.error("Unexpected error:", error);
  setError("Something went wrong. Please try again.");
}
```

### Using Type Guards

```typescript
import {
  isFido2Error,
  isFido2AbortError,
} from "@joinmeow/cognito-passwordless-auth";

try {
  await fido2CreateCredential({ friendlyName: "My Device" });
} catch (error) {
  if (isFido2AbortError(error)) {
    // User cancelled - no error message needed
    return;
  }

  if (isFido2Error(error)) {
    // Log technical details
    console.error(`Error ${error.code}:`, error.message);

    // Show user-friendly message
    showNotification(error.userMessage);

    // Access error-specific properties
    if (error instanceof Fido2ValidationError) {
      console.log("Invalid value:", error.invalidValue);
    }
  }
}
```

### React Hook Example

```typescript
import { useState } from "react";
import {
  authenticateWithFido2,
  Fido2AbortError,
  isFido2Error,
} from "@joinmeow/cognito-passwordless-auth";

function usePasskeyAuth() {
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const signIn = async (username: string, signal?: AbortSignal) => {
    setLoading(true);
    setError(null);

    try {
      const { signedIn } = authenticateWithFido2({
        username,
        credentialGetter: (options) =>
          fido2getCredential({ ...options, signal }),
      });

      const tokens = await signedIn;
      return tokens;
    } catch (err) {
      // User cancelled - don't show error
      if (err instanceof Fido2AbortError) {
        return null;
      }

      // Show user-friendly message for all Fido2 errors
      if (isFido2Error(err)) {
        console.error(err.message); // Log technical details
        setError(err.userMessage); // Show friendly message
        return null;
      }

      // Unknown error
      setError("Authentication failed");
      return null;
    } finally {
      setLoading(false);
    }
  };

  return { signIn, loading, error };
}
```

### Component Cleanup Example

```typescript
import { useEffect, useRef } from 'react';
import {
  fido2getCredential,
  Fido2AbortError
} from '@joinmeow/cognito-passwordless-auth';

function PasskeyDialog({ onClose }) {
  const abortControllerRef = useRef<AbortController>();

  useEffect(() => {
    const abortController = new AbortController();
    abortControllerRef.current = abortController;

    const authenticate = async () => {
      try {
        const credential = await fido2getCredential({
          challenge: 'base64-challenge',
          signal: abortController.signal  // ← Pass signal
        });

        handleSuccess(credential);

      } catch (error) {
        // Component unmounted - ignore abort error
        if (error instanceof Fido2AbortError) {
          return;
        }

        handleError(error);
      }
    };

    authenticate();

    // Cleanup: abort on unmount
    return () => {
      abortController.abort();
    };
  }, []);

  return <div>Authenticating...</div>;
}
```

## Error Properties

### Fido2Error (base)

- `message: string` - Technical error message for developers and logging
- `userMessage: string` - User-friendly passkey message for UI display
- `code: string` - Machine-readable error code
- `cause?: unknown` - Original error that caused this error
- `name: string` - Error class name
- `stack?: string` - Stack trace

### Fido2ValidationError

All base properties plus:

- `invalidValue?: unknown` - The value that failed validation

### Fido2NetworkError

All base properties plus:

- `statusCode?: number` - HTTP status code
- `response?: unknown` - Server response body

## Error Codes

| Code                     | Error Class          | User Message                               | Developer Message                   |
| ------------------------ | -------------------- | ------------------------------------------ | ----------------------------------- |
| `WEBAUTHN_ABORTED`       | Fido2AbortError      | "Passkey verification was cancelled"       | User cancelled or operation aborted |
| `CREDENTIAL_ERROR`       | Fido2CredentialError | "Unable to complete passkey operation"     | Credential operation failed         |
| `CONFIG_ERROR`           | Fido2ConfigError     | "Passkeys are not properly configured"     | Missing or invalid configuration    |
| `VALIDATION_ERROR`       | Fido2ValidationError | "Unable to verify passkey"                 | Data validation failed              |
| `AUTH_ERROR`             | Fido2AuthError       | "Authentication with passkey failed"       | Authentication/authorization failed |
| `NETWORK_ERROR`          | Fido2NetworkError    | "Unable to connect to passkey service"     | Server/network request failed       |
| `WEBAUTHN_UNKNOWN_ERROR` | Fido2Error           | "Something went wrong with your passkey"   | Client-specific unknown error       |
| `WEBAUTHN_ERROR`         | Fido2Error           | "Unable to use passkey. Please try again." | Generic WebAuthn error              |

## Browser DOMException Errors (WebAuthn Level 2 Spec)

The library automatically converts WebAuthn DOMExceptions to appropriate Fido2Error subclasses with user-friendly passkey messages. This covers all errors defined in the **WebAuthn Level 2** specification.

### navigator.credentials.create() Errors

| DOMException        | Converted To         | User Message                                                 | Technical Details                                                                |
| ------------------- | -------------------- | ------------------------------------------------------------ | -------------------------------------------------------------------------------- |
| `AbortError`        | Fido2AbortError      | "Passkey verification was cancelled"                         | Operation cancelled via AbortController or timeout                               |
| `NotAllowedError`   | Fido2CredentialError | "Passkey access was denied. Please try again."               | User cancelled ceremony, no user gesture, or permission denied                   |
| `InvalidStateError` | Fido2CredentialError | "This passkey is already registered"                         | Authenticator recognized entry in excludeCredentials after user consent          |
| `NotSupportedError` | Fido2ConfigError     | "Passkeys are not supported on this device"                  | No pubKeyCredParams had type="public-key", or algorithms not supported           |
| `SecurityError`     | Fido2ConfigError     | "Passkeys cannot be used on this website"                    | Invalid domain, rp.id not valid, or related origins validation failed            |
| `ConstraintError`   | Fido2ValidationError | "Your device doesn't support the required security features" | residentKey=required but not supported, or userVerification=required unavailable |
| `UnknownError`      | Fido2Error           | "Something went wrong with your passkey"                     | Client-specific error that doesn't fit other categories                          |

### navigator.credentials.get() Errors

| DOMException        | Converted To         | User Message                                   | Technical Details                                              |
| ------------------- | -------------------- | ---------------------------------------------- | -------------------------------------------------------------- |
| `AbortError`        | Fido2AbortError      | "Passkey verification was cancelled"           | Operation cancelled via AbortController or timeout             |
| `NotAllowedError`   | Fido2CredentialError | "Passkey access was denied. Please try again." | User cancelled ceremony, no user gesture, or permission denied |
| `InvalidStateError` | Fido2CredentialError | "This passkey is already registered"           | Authenticator is in invalid state                              |
| `SecurityError`     | Fido2ConfigError     | "Passkeys cannot be used on this website"      | Invalid domain or HTTPS required                               |
| `UnknownError`      | Fido2Error           | "Something went wrong with your passkey"       | Client-specific error that doesn't fit other categories        |

### Error Conversion Examples

```typescript
// Browser throws NotAllowedError
// Library converts to Fido2CredentialError with dual messaging

try {
  await fido2getCredential({ challenge });
} catch (error) {
  if (error instanceof Fido2CredentialError) {
    console.log("Error code:", error.code); // "CREDENTIAL_ERROR"
    console.log("Technical:", error.message); // "Operation not allowed..."
    console.log("User-friendly:", error.userMessage); // "Passkey access was denied..."
    console.log("Original DOMException:", error.cause); // NotAllowedError
  }
}
```

## Best Practices

1. **Use `userMessage` for UI display** - Show `error.userMessage` to users, log `error.message` for debugging
2. **Always handle Fido2AbortError silently** - Don't show errors when users cancel
3. **Use type guards** - `instanceof` or `isFido2Error()` for type safety
4. **Check error codes** - Use `error.code` for programmatic handling
5. **Log technical details** - Send `error.message` and `error.cause` to error tracking (Sentry, etc.)
6. **Pass AbortSignal** - Always pass abort signals for proper cleanup
7. **Use passkey language** - All `userMessage` properties use "passkey" terminology for consistency

## Migration from Old Code

**Before:**

```typescript
try {
  await fido2getCredential({ challenge });
} catch (err) {
  // Can't tell what went wrong!
  alert("Something failed");
}
```

**After (with user-friendly messages):**

```typescript
try {
  await fido2getCredential({ challenge });
} catch (err) {
  // Don't show error when user cancels
  if (err instanceof Fido2AbortError) return;

  // Show user-friendly passkey message
  if (isFido2Error(err)) {
    console.error(err.message); // Log technical details
    alert(err.userMessage); // Show friendly passkey message
    return;
  }

  // Unknown error
  alert("Authentication failed");
}
```

## WebAuthn Specification Compliance

This error handling implementation is fully compliant with the **[WebAuthn Level 2 specification](https://www.w3.org/TR/webauthn-2/)** published by W3C on April 8, 2021.

### Specification Coverage

**All DOMException errors from the spec are handled:**

✅ **navigator.credentials.create()** - 7 error types

- AbortError, ConstraintError, InvalidStateError, NotSupportedError, SecurityError, NotAllowedError, UnknownError

✅ **navigator.credentials.get()** - 5 error types

- AbortError, InvalidStateError, SecurityError, NotAllowedError, UnknownError

✅ **Simple exceptions** (not caught, propagate as-is)

- TypeError for invalid options

### Error Mapping Strategy

The library uses a **defensive error handling** approach with dual messaging:

1. **Wrap WebAuthn API calls** in try-catch blocks
2. **Detect DOMException** instances thrown by browser
3. **Convert to typed errors** using `fromDOMException()` helper
4. **Preserve original error** in the `cause` property for debugging
5. **Provide dual messages**:
   - `message`: Technical details for developers
   - `userMessage`: User-friendly passkey language

### Why This Matters

**Type Safety**: Your TypeScript code can use `instanceof` checks for precise error handling

**Debuggability**: Original browser errors preserved in `cause` property with technical `message`

**User Experience**: Built-in user-friendly `userMessage` using passkey terminology

**Developer Experience**: No manual message translation needed - just use `error.userMessage`

**Future Proof**: As browsers update WebAuthn implementations, error handling remains consistent

**Cross-Browser**: Same error handling works across Chrome, Safari, Firefox, and Edge

### References

- [WebAuthn Level 2 Specification](https://www.w3.org/TR/webauthn-2/)
- [WebAuthn Level 3 (Draft)](https://www.w3.org/TR/webauthn-3/)
- [FIDO Alliance](https://fidoalliance.org/)
- [MDN Web Authentication API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Authentication_API)
