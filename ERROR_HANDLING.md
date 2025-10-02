# Error Handling Guide

## Custom Error Classes

The library now provides typed error classes for better error handling in your application.

### Error Hierarchy

```typescript
Fido2Error (base class)
├── Fido2AbortError          - Operation cancelled by user or application
├── Fido2CredentialError     - Credential operations failed
├── Fido2ConfigError         - Configuration missing or invalid
├── Fido2ValidationError     - Validation of data failed
├── Fido2AuthError          - Authentication/authorization failed
└── Fido2NetworkError       - Server/network requests failed
```

## Usage Examples

### Basic Error Handling

```typescript
import {
  authenticateWithFido2,
  Fido2AbortError,
  Fido2CredentialError,
  Fido2ConfigError,
  isFido2AbortError,
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
    // No passkey found or credential error
    setError("No passkey found. Please use password or register a passkey.");
    return;
  }

  if (error instanceof Fido2ConfigError) {
    // Developer error - WebAuthn not configured
    console.error("WebAuthn not configured properly", error);
    setError("Authentication unavailable. Please contact support.");
    return;
  }

  // Note: DOMExceptions are automatically converted to Fido2Error subclasses
  // by the library, so you don't need to handle them separately!

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
    // User cancelled
    return;
  }

  if (isFido2Error(error)) {
    // Any Fido2Error subclass
    console.error(`Error ${error.code}:`, error.message);

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
  Fido2CredentialError,
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

      // No passkey found
      if (err instanceof Fido2CredentialError) {
        setError("No passkey found for this account");
        return null;
      }

      // Generic Fido2 error
      if (isFido2Error(err)) {
        setError(err.message);
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

- `message: string` - Human-readable error message
- `code: string` - Machine-readable error code
- `cause?: unknown` - Original error that caused this error
- `name: string` - Error class name
- `stack?: string` - Stack trace

### Fido2ValidationError

- `invalidValue?: unknown` - The value that failed validation

### Fido2NetworkError

- `statusCode?: number` - HTTP status code
- `response?: unknown` - Server response body

## Error Codes

| Code                     | Error Class          | Meaning                             |
| ------------------------ | -------------------- | ----------------------------------- |
| `WEBAUTHN_ABORTED`       | Fido2AbortError      | User cancelled or operation aborted |
| `CREDENTIAL_ERROR`       | Fido2CredentialError | Credential operation failed         |
| `CONFIG_ERROR`           | Fido2ConfigError     | Missing or invalid configuration    |
| `VALIDATION_ERROR`       | Fido2ValidationError | Data validation failed              |
| `AUTH_ERROR`             | Fido2AuthError       | Authentication/authorization failed |
| `NETWORK_ERROR`          | Fido2NetworkError    | Server/network request failed       |
| `WEBAUTHN_UNKNOWN_ERROR` | Fido2Error           | Client-specific unknown error       |
| `WEBAUTHN_ERROR`         | Fido2Error           | Generic WebAuthn error              |

## Browser DOMException Errors (WebAuthn Level 2 Spec)

The library automatically converts WebAuthn DOMExceptions to appropriate Fido2Error subclasses. This covers all errors defined in the **WebAuthn Level 2** specification.

### navigator.credentials.create() Errors

| DOMException        | Converted To         | When It Occurs                                                                   |
| ------------------- | -------------------- | -------------------------------------------------------------------------------- |
| `AbortError`        | Fido2AbortError      | Operation cancelled via AbortController or timeout                               |
| `NotAllowedError`   | Fido2CredentialError | User cancelled ceremony, no user gesture, or permission denied                   |
| `InvalidStateError` | Fido2CredentialError | Authenticator recognized entry in excludeCredentials after user consent          |
| `NotSupportedError` | Fido2ConfigError     | No pubKeyCredParams had type="public-key", or algorithms not supported           |
| `SecurityError`     | Fido2ConfigError     | Invalid domain, rp.id not valid, or related origins validation failed            |
| `ConstraintError`   | Fido2ValidationError | residentKey=required but not supported, or userVerification=required unavailable |
| `UnknownError`      | Fido2Error           | Client-specific error that doesn't fit other categories                          |

### navigator.credentials.get() Errors

| DOMException        | Converted To         | When It Occurs                                                 |
| ------------------- | -------------------- | -------------------------------------------------------------- |
| `AbortError`        | Fido2AbortError      | Operation cancelled via AbortController or timeout             |
| `NotAllowedError`   | Fido2CredentialError | User cancelled ceremony, no user gesture, or permission denied |
| `InvalidStateError` | Fido2CredentialError | Authenticator is in invalid state                              |
| `SecurityError`     | Fido2ConfigError     | Invalid domain or HTTPS required                               |
| `UnknownError`      | Fido2Error           | Client-specific error that doesn't fit other categories        |

### Error Conversion Examples

```typescript
// Browser throws NotAllowedError
// Library converts to Fido2CredentialError with cause

try {
  await fido2getCredential({ challenge });
} catch (error) {
  if (error instanceof Fido2CredentialError) {
    console.log("Error code:", error.code); // "CREDENTIAL_ERROR"
    console.log("Original DOMException:", error.cause); // NotAllowedError
  }
}
```

## Best Practices

1. **Always handle Fido2AbortError silently** - Don't show errors when users cancel
2. **Use type guards** - `instanceof` or `isFido2Error()` for type safety
3. **Check error codes** - Use `error.code` for programmatic handling
4. **Log unknown errors** - Send to error tracking service (Sentry, etc.)
5. **Provide helpful messages** - Convert technical errors to user-friendly text
6. **Pass AbortSignal** - Always pass abort signals for proper cleanup

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

**After:**

```typescript
try {
  await fido2getCredential({ challenge });
} catch (err) {
  if (err instanceof Fido2AbortError) return;

  if (err instanceof Fido2CredentialError) {
    alert("No passkey found");
    return;
  }

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

The library uses a **defensive error handling** approach:

1. **Wrap WebAuthn API calls** in try-catch blocks
2. **Detect DOMException** instances thrown by browser
3. **Convert to typed errors** using `fromDOMException()` helper
4. **Preserve original error** in the `cause` property for debugging
5. **Provide user-friendly messages** while maintaining technical accuracy

### Why This Matters

**Type Safety**: Your TypeScript code can use `instanceof` checks for precise error handling

**Debuggability**: Original browser errors preserved in `cause` property

**User Experience**: Translate technical WebAuthn errors into helpful user messages

**Future Proof**: As browsers update WebAuthn implementations, error handling remains consistent

**Cross-Browser**: Same error handling works across Chrome, Safari, Firefox, and Edge

### References

- [WebAuthn Level 2 Specification](https://www.w3.org/TR/webauthn-2/)
- [WebAuthn Level 3 (Draft)](https://www.w3.org/TR/webauthn-3/)
- [FIDO Alliance](https://fidoalliance.org/)
- [MDN Web Authentication API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Authentication_API)
