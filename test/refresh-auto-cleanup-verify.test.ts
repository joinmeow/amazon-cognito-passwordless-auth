/* eslint-disable @typescript-eslint/no-var-requires --
   jest.isolateModules only isolates modules loaded with require(); a static
   import would resolve from the shared registry and defeat the whole point. */
// Module-LOAD behavior of client/refresh.ts's page-lifecycle listeners.
//
// The listeners are registered at import time, which the other auto-cleanup
// suite cannot observe (its spies install after the shared module instance
// already loaded — it used to pre-seed a map and assert `has()`, which was
// vacuous). jest.isolateModules gives a fresh module registry, so requiring
// refresh.ts INSIDE it re-runs the top-level registration against our spies.

describe("Refresh system page-lifecycle listeners (module load)", () => {
  test("registers beforeunload + pagehide, and deliberately NO unload listener", () => {
    const added: string[] = [];
    const addSpy = jest
      .spyOn(globalThis, "addEventListener")
      .mockImplementation(((event: string) => {
        added.push(event);
      }) as typeof globalThis.addEventListener);
    // Swallow the doc-level visibilitychange registration too, so the fresh
    // module instance leaks no live listeners into this jsdom.
    const docAddSpy = jest
      .spyOn(document, "addEventListener")
      .mockImplementation(() => {});

    let freshRefresh: typeof import("../client/refresh.js") | undefined;
    try {
      jest.isolateModules(() => {
        // The fresh registry has a fresh (unconfigured) config module too;
        // configure it so the teardown's debug logging can run.
        const { configure } =
          require("../client/config.js") as typeof import("../client/config.js");
        configure({ clientId: "testClient", cognitoIdpEndpoint: "us-west-2" });
        freshRefresh =
          require("../client/refresh.js") as typeof import("../client/refresh.js");
      });

      expect(added).toContain("beforeunload");
      expect(added).toContain("pagehide");
      // An "unload" listener makes the page ineligible for the back/forward
      // cache in desktop Chrome and Firefox, and pagehide fires in every case
      // unload does — so registering one is pure downside.
      // https://web.dev/articles/bfcache
      expect(added).not.toContain("unload");
    } finally {
      addSpy.mockRestore();
      docAddSpy.mockRestore();
      // Tear down the fresh instance's watchdog timer.
      freshRefresh?.cleanupRefreshSystem();
    }
  });

  test("a pagehide event triggers the auto-cleanup handler", () => {
    const logs: string[] = [];
    let freshRefresh: typeof import("../client/refresh.js") | undefined;
    // Isolate BOTH refresh.ts and its config module, so we can point the
    // fresh instance's debug at our log capture.
    jest.isolateModules(() => {
      const { configure } =
        require("../client/config.js") as typeof import("../client/config.js");
      configure({
        clientId: "testClient",
        cognitoIdpEndpoint: "us-west-2",
        debug: (...args: unknown[]) => {
          logs.push(args.map(String).join(" "));
        },
      });
      freshRefresh =
        require("../client/refresh.js") as typeof import("../client/refresh.js");
    });

    try {
      globalThis.dispatchEvent(new Event("pagehide"));
      expect(
        logs.some((l) => l.includes("Auto-cleanup triggered on page unload"))
      ).toBe(true);
    } finally {
      freshRefresh?.cleanupRefreshSystem();
    }
  });
});
