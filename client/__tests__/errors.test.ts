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

import {
  Fido2Error,
  Fido2AbortError,
  Fido2CredentialError,
  Fido2ConfigError,
  Fido2ValidationError,
  Fido2AuthError,
  Fido2NetworkError,
  isFido2Error,
  isFido2AbortError,
  fromDOMException,
} from "../errors.js";

describe("Fido2Error classes", () => {
  describe("Fido2Error (base class)", () => {
    it("should create error with message, code, and optional cause", () => {
      const cause = new Error("original error");
      const error = new Fido2Error("Test error", "TEST_CODE", undefined, cause);

      expect(error.message).toBe("Test error");
      expect(error.code).toBe("TEST_CODE");
      expect(error.cause).toBe(cause);
      expect(error.name).toBe("Fido2Error");
      expect(error).toBeInstanceOf(Error);
    });

    it("should work without cause", () => {
      const error = new Fido2Error("Test error", "TEST_CODE");

      expect(error.message).toBe("Test error");
      expect(error.code).toBe("TEST_CODE");
      expect(error.cause).toBeUndefined();
    });

    it("should have stack trace", () => {
      const error = new Fido2Error("Test error", "TEST_CODE");
      expect(error.stack).toBeDefined();
    });
  });

  describe("Fido2AbortError", () => {
    it("should create abort error with default message", () => {
      const error = new Fido2AbortError();

      expect(error.message).toBe("WebAuthn operation was cancelled");
      expect(error.code).toBe("WEBAUTHN_ABORTED");
      expect(error.name).toBe("Fido2AbortError");
      expect(error).toBeInstanceOf(Fido2Error);
    });

    it("should create abort error with custom message", () => {
      const error = new Fido2AbortError("User cancelled");

      expect(error.message).toBe("User cancelled");
      expect(error.code).toBe("WEBAUTHN_ABORTED");
    });
  });

  describe("Fido2CredentialError", () => {
    it("should create credential error", () => {
      const cause = new DOMException("Not allowed", "NotAllowedError");
      const error = new Fido2CredentialError("No credential found", cause);

      expect(error.message).toBe("No credential found");
      expect(error.code).toBe("CREDENTIAL_ERROR");
      expect(error.name).toBe("Fido2CredentialError");
      expect(error.cause).toBe(cause);
    });
  });

  describe("Fido2ConfigError", () => {
    it("should create config error", () => {
      const error = new Fido2ConfigError("Missing configuration");

      expect(error.message).toBe("Missing configuration");
      expect(error.code).toBe("CONFIG_ERROR");
      expect(error.name).toBe("Fido2ConfigError");
    });
  });

  describe("Fido2ValidationError", () => {
    it("should create validation error with invalid value", () => {
      const invalidValue = { foo: "bar" };
      const error = new Fido2ValidationError("Invalid options", invalidValue);

      expect(error.message).toBe("Invalid options");
      expect(error.code).toBe("VALIDATION_ERROR");
      expect(error.name).toBe("Fido2ValidationError");
      expect(error.invalidValue).toBe(invalidValue);
    });

    it("should work without invalidValue", () => {
      const error = new Fido2ValidationError("Invalid options");
      expect(error.invalidValue).toBeUndefined();
    });
  });

  describe("Fido2AuthError", () => {
    it("should create auth error", () => {
      const error = new Fido2AuthError("No token available");

      expect(error.message).toBe("No token available");
      expect(error.code).toBe("AUTH_ERROR");
      expect(error.name).toBe("Fido2AuthError");
    });
  });

  describe("Fido2NetworkError", () => {
    it("should create network error with status code and response", () => {
      const response = { error: "Not found" };
      const error = new Fido2NetworkError("Request failed", 404, response);

      expect(error.message).toBe("Request failed");
      expect(error.code).toBe("NETWORK_ERROR");
      expect(error.name).toBe("Fido2NetworkError");
      expect(error.statusCode).toBe(404);
      expect(error.response).toBe(response);
    });

    it("should work without status code and response", () => {
      const error = new Fido2NetworkError("Network timeout");

      expect(error.statusCode).toBeUndefined();
      expect(error.response).toBeUndefined();
    });
  });
});

describe("Type guards", () => {
  describe("isFido2Error", () => {
    it("should return true for Fido2Error instances", () => {
      expect(isFido2Error(new Fido2Error("test", "TEST"))).toBe(true);
      expect(isFido2Error(new Fido2AbortError())).toBe(true);
      expect(isFido2Error(new Fido2CredentialError("test"))).toBe(true);
      expect(isFido2Error(new Fido2ConfigError("test"))).toBe(true);
      expect(isFido2Error(new Fido2ValidationError("test"))).toBe(true);
      expect(isFido2Error(new Fido2AuthError("test"))).toBe(true);
      expect(isFido2Error(new Fido2NetworkError("test"))).toBe(true);
    });

    it("should return false for non-Fido2Error instances", () => {
      expect(isFido2Error(new Error("test"))).toBe(false);
      expect(isFido2Error(new DOMException("test"))).toBe(false);
      expect(isFido2Error("test")).toBe(false);
      expect(isFido2Error(null)).toBe(false);
      expect(isFido2Error(undefined)).toBe(false);
      expect(isFido2Error({})).toBe(false);
    });
  });

  describe("isFido2AbortError", () => {
    it("should return true for Fido2AbortError instances", () => {
      expect(isFido2AbortError(new Fido2AbortError())).toBe(true);
    });

    it("should return false for other error types", () => {
      expect(isFido2AbortError(new Fido2Error("test", "TEST"))).toBe(false);
      expect(isFido2AbortError(new Fido2CredentialError("test"))).toBe(false);
      expect(isFido2AbortError(new Error("test"))).toBe(false);
      expect(isFido2AbortError(null)).toBe(false);
    });
  });
});

describe("fromDOMException", () => {
  describe("WebAuthn Level 2 specification compliance", () => {
    it("should convert AbortError to Fido2AbortError", () => {
      const domError = new DOMException("User cancelled", "AbortError");
      const error = fromDOMException(domError);

      expect(error).toBeInstanceOf(Fido2AbortError);
      expect(error.message).toBe("WebAuthn operation was aborted");
      expect(error.code).toBe("WEBAUTHN_ABORTED");
    });

    it("should convert NotAllowedError to Fido2CredentialError", () => {
      const domError = new DOMException("Not allowed", "NotAllowedError");
      const error = fromDOMException(domError);

      expect(error).toBeInstanceOf(Fido2CredentialError);
      expect(error.message).toContain("not allowed");
      expect(error.code).toBe("CREDENTIAL_ERROR");
      expect(error.cause).toBe(domError);
    });

    it("should convert InvalidStateError to Fido2CredentialError", () => {
      const domError = new DOMException("Invalid state", "InvalidStateError");
      const error = fromDOMException(domError);

      expect(error).toBeInstanceOf(Fido2CredentialError);
      expect(error.message).toContain("invalid state");
      expect(error.code).toBe("CREDENTIAL_ERROR");
      expect(error.cause).toBe(domError);
    });

    it("should convert NotSupportedError to Fido2ConfigError", () => {
      const domError = new DOMException("Not supported", "NotSupportedError");
      const error = fromDOMException(domError);

      expect(error).toBeInstanceOf(Fido2ConfigError);
      expect(error.message).toContain("not supported");
      expect(error.code).toBe("CONFIG_ERROR");
    });

    it("should convert SecurityError to Fido2ConfigError", () => {
      const domError = new DOMException("Security error", "SecurityError");
      const error = fromDOMException(domError);

      expect(error).toBeInstanceOf(Fido2ConfigError);
      expect(error.message).toContain("Security requirements");
      expect(error.code).toBe("CONFIG_ERROR");
    });

    it("should convert ConstraintError to Fido2ValidationError", () => {
      const domError = new DOMException("Constraint failed", "ConstraintError");
      const error = fromDOMException(domError);

      expect(error).toBeInstanceOf(Fido2ValidationError);
      expect(error.message).toContain("constraints not satisfied");
      expect(error.code).toBe("VALIDATION_ERROR");
      expect((error as Fido2ValidationError).invalidValue).toBe(domError);
    });

    it("should convert UnknownError to Fido2Error", () => {
      const domError = new DOMException("Unknown error", "UnknownError");
      const error = fromDOMException(domError);

      expect(error).toBeInstanceOf(Fido2Error);
      expect(error.message).toBe("Unknown WebAuthn error occurred");
      expect(error.code).toBe("WEBAUTHN_UNKNOWN_ERROR");
      expect(error.cause).toBe(domError);
    });

    it("should convert unknown DOMException to generic Fido2Error", () => {
      const domError = new DOMException("Random error", "RandomError");
      const error = fromDOMException(domError);

      expect(error).toBeInstanceOf(Fido2Error);
      expect(error.message).toContain("WebAuthn operation failed");
      expect(error.message).toContain("Random error");
      expect(error.code).toBe("WEBAUTHN_ERROR");
      expect(error.cause).toBe(domError);
    });
  });

  describe("Error preservation", () => {
    it("should preserve original error in cause property", () => {
      const domError = new DOMException("Test message", "NotAllowedError");
      const error = fromDOMException(domError);

      expect(error.cause).toBe(domError);
      expect((error.cause as DOMException).name).toBe("NotAllowedError");
      expect((error.cause as DOMException).message).toBe("Test message");
    });

    it("should not preserve cause for AbortError (no cause parameter)", () => {
      const domError = new DOMException("Aborted", "AbortError");
      const error = fromDOMException(domError);

      expect(error.cause).toBeUndefined();
    });
  });
});

describe("Error inheritance chain", () => {
  it("should maintain proper instanceof relationships", () => {
    const abortError = new Fido2AbortError();

    expect(abortError instanceof Fido2AbortError).toBe(true);
    expect(abortError instanceof Fido2Error).toBe(true);
    expect(abortError instanceof Error).toBe(true);
  });

  it("should allow catching by base class", () => {
    const errors = [
      new Fido2AbortError(),
      new Fido2CredentialError("test"),
      new Fido2ConfigError("test"),
      new Fido2ValidationError("test"),
      new Fido2AuthError("test"),
      new Fido2NetworkError("test"),
    ];

    errors.forEach((error) => {
      try {
        throw error;
      } catch (e) {
        expect(e).toBeInstanceOf(Fido2Error);
        expect(e).toBeInstanceOf(Error);
      }
    });
  });
});
