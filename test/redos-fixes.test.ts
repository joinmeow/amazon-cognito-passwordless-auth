import { configure } from "../client/config.js";
import { throwIfNot2xx } from "../client/util.js";
import { getAuthorizeEndpoint } from "../client/config.js";

const errResponse = (type: string, message: string) => ({
  ok: false,
  status: 400,
  json: () => Promise.resolve({ __type: type, message }),
});

describe("throwIfNot2xx UserLambdaValidationException message extraction", () => {
  const extract = async (message: string): Promise<string> => {
    try {
      await throwIfNot2xx(
        errResponse("UserLambdaValidationException", message) as never
      );
      throw new Error("should have thrown");
    } catch (e) {
      return (e as Error).message;
    }
  };

  test("extracts the text after 'failed with error '", async () => {
    expect(
      await extract("PreSignUp failed with error Email domain not allowed.")
    ).toBe("Email domain not allowed.");
  });

  test("leaves the message unchanged when the marker is absent", async () => {
    expect(await extract("Some other validation message")).toBe(
      "Some other validation message"
    );
  });

  test("leaves the message unchanged when there is no prefix or no suffix", async () => {
    // No prefix (marker at start) → unchanged
    expect(await extract("failed with error X")).toBe("failed with error X");
    // No suffix (marker at end) → unchanged
    expect(await extract("Trigger failed with error ")).toBe(
      "Trigger failed with error "
    );
  });

  test("returns quickly (no ReDoS) on a pathological message", async () => {
    // The old /^.+failed with error (.+)$/ backtracks polynomially on a long
    // near-miss; this must complete well under any sane timeout.
    const pathological = "a".repeat(200_000) + "failed with erro"; // near-miss
    const start = Date.now();
    const out = await extract(pathological);
    expect(Date.now() - start).toBeLessThan(1000);
    expect(out).toBe(pathological); // no marker match → unchanged
  });
});

describe("endpoint trailing-slash normalization", () => {
  test("trims trailing slashes from a custom https endpoint", () => {
    configure({
      clientId: "c",
      cognitoIdpEndpoint: "https://auth.example.com///",
      hostedUi: {
        domain: "auth.example.com////",
        redirectSignIn: "https://app.example.com/cb",
      },
    });
    // getAuthorizeEndpoint builds on the normalized hostedUi domain
    expect(getAuthorizeEndpoint()).toBe(
      "https://auth.example.com/oauth2/authorize"
    );
  });

  test("returns quickly (no ReDoS) on a long run of trailing slashes", () => {
    const start = Date.now();
    configure({
      clientId: "c",
      cognitoIdpEndpoint: "https://auth.example.com",
      hostedUi: {
        domain: "https://auth.example.com" + "/".repeat(200_000),
        redirectSignIn: "https://app.example.com/cb",
      },
    });
    expect(getAuthorizeEndpoint()).toBe(
      "https://auth.example.com/oauth2/authorize"
    );
    expect(Date.now() - start).toBeLessThan(1000);
  });
});
