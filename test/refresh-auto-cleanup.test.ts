import { configure } from "../client/config.js";
import { scheduleRefresh, cleanupRefreshSystem } from "../client/refresh.js";
import { storeTokens } from "../client/storage.js";

// Helper to create JWT tokens
const createJWT = (claims: Record<string, unknown>) => {
  const header = btoa(JSON.stringify({ alg: "HS256", typ: "JWT" }))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
  const payload = btoa(JSON.stringify(claims))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
  return `${header}.${payload}.signature`;
};

describe("Auto-Cleanup Functionality", () => {
  let debugLogs: string[] = [];
  let eventListeners: Map<string, Set<EventListener>>;
  let originalAddEventListener: typeof globalThis.addEventListener;
  let originalRemoveEventListener: typeof globalThis.removeEventListener;
  let originalDocAddEventListener: typeof document.addEventListener;
  let originalDocRemoveEventListener: typeof document.removeEventListener;

  beforeEach(() => {
    debugLogs = [];
    eventListeners = new Map();

    // Mock addEventListener to track listeners
    originalAddEventListener = globalThis.addEventListener;
    originalRemoveEventListener = globalThis.removeEventListener;
    originalDocAddEventListener = document.addEventListener;
    originalDocRemoveEventListener = document.removeEventListener;

    globalThis.addEventListener = jest.fn((event: string, handler: EventListener) => {
      if (!eventListeners.has(event)) {
        eventListeners.set(event, new Set());
      }
      eventListeners.get(event)!.add(handler);
      originalAddEventListener.call(globalThis, event, handler);
    }) as any;

    globalThis.removeEventListener = jest.fn((event: string, handler: EventListener) => {
      eventListeners.get(event)?.delete(handler);
      originalRemoveEventListener.call(globalThis, event, handler);
    }) as any;

    document.addEventListener = jest.fn((event: string, handler: EventListener) => {
      const docEvent = `doc:${event}`;
      if (!eventListeners.has(docEvent)) {
        eventListeners.set(docEvent, new Set());
      }
      eventListeners.get(docEvent)!.add(handler);
      originalDocAddEventListener.call(document, event, handler);
    }) as any;

    document.removeEventListener = jest.fn((event: string, handler: EventListener) => {
      const docEvent = `doc:${event}`;
      eventListeners.get(docEvent)?.delete(handler);
      originalDocRemoveEventListener.call(document, event, handler);
    }) as any;

    configure({
      clientId: "testClient",
      cognitoIdpEndpoint: "us-west-2",
      debug: (...args: any[]) => {
        debugLogs.push(args.join(" "));
      },
    });
  });

  afterEach(() => {
    // Restore original functions
    globalThis.addEventListener = originalAddEventListener;
    globalThis.removeEventListener = originalRemoveEventListener;
    document.addEventListener = originalDocAddEventListener;
    document.removeEventListener = originalDocRemoveEventListener;
    
    // Clean up
    cleanupRefreshSystem();
  });

  test("should register auto-cleanup listeners on module load", () => {
    // The refresh module initializes on import, so listeners should already be registered
    
    // Check that beforeunload listener was added
    expect(eventListeners.has("beforeunload")).toBe(true);
    expect(eventListeners.get("beforeunload")?.size).toBeGreaterThan(0);
    
    // Check that pagehide listener was added
    expect(eventListeners.has("pagehide")).toBe(true);
    expect(eventListeners.get("pagehide")?.size).toBeGreaterThan(0);
    
    // Check that unload listener was added
    expect(eventListeners.has("unload")).toBe(true);
    expect(eventListeners.get("unload")?.size).toBeGreaterThan(0);
    
    // Check that visibility change listener was added to document
    expect(eventListeners.has("doc:visibilitychange")).toBe(true);
    expect(eventListeners.get("doc:visibilitychange")?.size).toBeGreaterThan(0);
  });

  test("should trigger cleanup on beforeunload event", () => {
    // Clear logs
    debugLogs = [];
    
    // Trigger beforeunload event
    const beforeunloadEvent = new Event("beforeunload");
    globalThis.dispatchEvent(beforeunloadEvent);
    
    // Check that auto-cleanup was triggered
    const cleanupLog = debugLogs.find(log => 
      log.includes("Auto-cleanup triggered on page unload/hide")
    );
    expect(cleanupLog).toBeTruthy();
    
    // Check that cleanup system was called
    const systemCleanupLog = debugLogs.find(log => 
      log.includes("Cleaning up refresh system")
    );
    expect(systemCleanupLog).toBeTruthy();
  });

  test("should trigger cleanup on pagehide event", () => {
    // Clear logs
    debugLogs = [];
    
    // Trigger pagehide event
    const pagehideEvent = new Event("pagehide");
    globalThis.dispatchEvent(pagehideEvent);
    
    // Check that auto-cleanup was triggered
    const cleanupLog = debugLogs.find(log => 
      log.includes("Auto-cleanup triggered on page unload/hide")
    );
    expect(cleanupLog).toBeTruthy();
  });

  test("should trigger cleanup on unload event", () => {
    // Clear logs
    debugLogs = [];
    
    // Trigger unload event
    const unloadEvent = new Event("unload");
    globalThis.dispatchEvent(unloadEvent);
    
    // Check that auto-cleanup was triggered
    const cleanupLog = debugLogs.find(log => 
      log.includes("Auto-cleanup triggered on page unload/hide")
    );
    expect(cleanupLog).toBeTruthy();
  });

  test("should remove all event listeners when cleanupRefreshSystem is called", () => {
    // Get initial listener counts
    const beforeUnloadCount = eventListeners.get("beforeunload")?.size || 0;
    const pageHideCount = eventListeners.get("pagehide")?.size || 0;
    const unloadCount = eventListeners.get("unload")?.size || 0;
    const visibilityCount = eventListeners.get("doc:visibilitychange")?.size || 0;
    
    // All should have at least one listener
    expect(beforeUnloadCount).toBeGreaterThan(0);
    expect(pageHideCount).toBeGreaterThan(0);
    expect(unloadCount).toBeGreaterThan(0);
    expect(visibilityCount).toBeGreaterThan(0);
    
    // Call cleanup
    cleanupRefreshSystem();
    
    // Check that removeEventListener was called for auto-cleanup handlers
    expect(globalThis.removeEventListener).toHaveBeenCalledWith("beforeunload", expect.any(Function));
    expect(globalThis.removeEventListener).toHaveBeenCalledWith("pagehide", expect.any(Function));
    expect(globalThis.removeEventListener).toHaveBeenCalledWith("unload", expect.any(Function));
    
    // Check that document.removeEventListener was called for visibility
    expect(document.removeEventListener).toHaveBeenCalledWith("visibilitychange", expect.any(Function));
  });

  test("should not require manual cleanup - handles page lifecycle automatically", async () => {
    // Store tokens to enable refresh scheduling
    const now = Date.now();
    const tokens = {
      accessToken: createJWT({
        sub: "user123",
        username: "testuser",
        exp: Math.floor((now + 3600000) / 1000),
        iat: Math.floor(now / 1000),
      }),
      refreshToken: "test-refresh-token",
      username: "testuser",
      expireAt: new Date(now + 3600000),
    };

    await storeTokens(tokens);
    await scheduleRefresh();
    
    // Clear logs
    debugLogs = [];
    
    // Simulate page unload - this would happen automatically in a real browser
    const beforeunloadEvent = new Event("beforeunload");
    globalThis.dispatchEvent(beforeunloadEvent);
    
    // Verify cleanup happened automatically
    expect(debugLogs.some(log => log.includes("Auto-cleanup triggered"))).toBe(true);
    expect(debugLogs.some(log => log.includes("Cleaning up refresh system"))).toBe(true);
    
    // No manual cleanup call was needed!
  });

  test("auto-cleanup should be idempotent - safe to call multiple times", () => {
    // Clear logs
    debugLogs = [];
    
    // Trigger multiple cleanup events
    globalThis.dispatchEvent(new Event("beforeunload"));
    globalThis.dispatchEvent(new Event("pagehide"));
    globalThis.dispatchEvent(new Event("unload"));
    
    // Count how many times cleanup was triggered
    const cleanupCalls = debugLogs.filter(log => 
      log.includes("Cleaning up refresh system")
    ).length;
    
    // Should be called 3 times (once for each event)
    expect(cleanupCalls).toBe(3);
    
    // And it should be safe - no errors
  });
});