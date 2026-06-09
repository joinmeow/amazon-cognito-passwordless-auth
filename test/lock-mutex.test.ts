import { configure } from "../client/config.js";
import { withStorageLock } from "../client/lock.js";

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

/**
 * Regression tests for cross-tab mutual exclusion of the storage lock:
 * - a storage event fired by ANOTHER WAITER acquiring the lock must not be
 *   mistaken for a release
 * - after waiting, acquisition must re-check that the lock is actually free
 *   before writing (no blind clobbering)
 * - long critical sections must renew the lock via heartbeat so other tabs
 *   don't declare it stale and start a concurrent refresh
 * - a heartbeat renewal must stand down (not write / stop renewing) when the
 *   lock went stale and another tab took it over, and must verify its own
 *   write afterwards so a competing takeover is never clobbered
 * - release must not remove a lock legitimately taken over by another tab
 */
describe("Storage Lock mutual exclusion", () => {
  let storageData: Map<string, string>;

  const mockStorage = {
    getItem: async (key: string) => storageData.get(key) ?? null,
    setItem: async (key: string, value: string) => {
      storageData.set(key, value);
    },
    removeItem: async (key: string) => {
      storageData.delete(key);
    },
  };

  beforeEach(() => {
    storageData = new Map();
    configure({
      clientId: "testClient",
      cognitoIdpEndpoint: "us-west-2",
      storage: mockStorage,
    });
  });

  test("waiter must not steal the lock when another waiter acquires it (storage event)", async () => {
    const key = "lock-steal-test";

    // Tab A (another tab) holds the lock
    const lockA = JSON.stringify({ id: "tab-A", timestamp: Date.now() });
    storageData.set(key, lockA);

    // Tab C (this process) waits for the lock
    let fnRan = false;
    const cPromise = withStorageLock(
      key,
      async () => {
        fnRan = true;
      },
      3000
    );

    // Give C time to start polling
    await sleep(30);

    // Tab A releases and tab B (another waiter in another tab) immediately
    // acquires: B's write fires a storage event in this tab
    const lockB = JSON.stringify({ id: "tab-B", timestamp: Date.now() });
    storageData.set(key, lockB);
    globalThis.dispatchEvent(
      new StorageEvent("storage", { key, oldValue: lockA, newValue: lockB })
    );

    // C must keep waiting: it must neither run its critical section nor
    // clobber B's lock
    await sleep(200);
    expect(fnRan).toBe(false);
    const heldLock = JSON.parse(storageData.get(key)!) as { id: string };
    expect(heldLock.id).toBe("tab-B");

    // Now B genuinely releases; C may acquire
    storageData.delete(key);
    globalThis.dispatchEvent(
      new StorageEvent("storage", { key, oldValue: lockB, newValue: null })
    );

    await cPromise;
    expect(fnRan).toBe(true);
  });

  test("spurious release event must not break mutual exclusion", async () => {
    const key = "lock-spurious-release-test";
    const order: string[] = [];

    // A (same process) holds the lock for a while
    const aPromise = withStorageLock(key, async () => {
      order.push("A-start");
      await sleep(300);
      order.push("A-end");
    });

    // Give A time to acquire
    await sleep(50);

    // B waits for the lock
    const bPromise = withStorageLock(
      key,
      async () => {
        order.push("B");
      },
      5000
    );
    await sleep(30);

    // A spurious "release" storage event arrives while A still holds the
    // lock; B must re-check storage and keep waiting instead of clobbering
    globalThis.dispatchEvent(
      new StorageEvent("storage", { key, oldValue: "x", newValue: null })
    );

    await Promise.all([aPromise, bPromise]);
    expect(order).toEqual(["A-start", "A-end", "B"]);
  });

  test("heartbeat renews the lock so long critical sections are not declared stale", async () => {
    jest.useFakeTimers();
    try {
      const key = "lock-heartbeat-test";
      const order: string[] = [];

      // Critical section longer (45s) than the stale-lock timeout (30s)
      const aPromise = withStorageLock(key, async () => {
        order.push("A-start");
        await sleep(45000);
        order.push("A-end");
      });

      // Let A acquire the lock
      await jest.advanceTimersByTimeAsync(100);
      expect(order).toEqual(["A-start"]);
      const initialLock = JSON.parse(storageData.get(key)!) as {
        timestamp: number;
      };

      // 35s in: without a heartbeat the lock would now be considered stale
      await jest.advanceTimersByTimeAsync(35000);
      const renewedLock = JSON.parse(storageData.get(key)!) as {
        timestamp: number;
      };
      expect(renewedLock.timestamp).toBeGreaterThan(initialLock.timestamp);
      expect(Date.now() - renewedLock.timestamp).toBeLessThan(30000);

      // A second contender must not be able to take over the (fresh) lock
      const bPromise = withStorageLock(
        key,
        async () => {
          order.push("B");
        },
        15000
      );
      await jest.advanceTimersByTimeAsync(5000);
      expect(order).toEqual(["A-start"]);

      // A finishes at 45s; B may then acquire
      await jest.advanceTimersByTimeAsync(10000);
      await aPromise;
      await jest.advanceTimersByTimeAsync(1000);
      await bPromise;
      expect(order).toEqual(["A-start", "A-end", "B"]);
    } finally {
      jest.useRealTimers();
    }
  });

  test("in-flight heartbeat renewal must not resurrect a released lock", async () => {
    jest.useFakeTimers();
    try {
      const key = "lock-heartbeat-race-test";

      // Storage whose next getItem can be held in flight: the value is read
      // immediately (while the holder still owns the lock) but the promise
      // only resolves later, after the critical section has finished — the
      // exact window in which a heartbeat write would resurrect the lock
      let interceptNextGet = false;
      let resumeHeartbeatRead: (() => void) | undefined;
      const gatedStorage = {
        getItem: (k: string): Promise<string | null> => {
          if (interceptNextGet) {
            interceptNextGet = false;
            const valueAtReadTime = storageData.get(k) ?? null;
            return new Promise((resolve) => {
              resumeHeartbeatRead = () => resolve(valueAtReadTime);
            });
          }
          return Promise.resolve(storageData.get(k) ?? null);
        },
        setItem: mockStorage.setItem,
        removeItem: mockStorage.removeItem,
      };
      configure({
        clientId: "testClient",
        cognitoIdpEndpoint: "us-west-2",
        storage: gatedStorage,
      });

      // Critical section ends shortly after the first heartbeat tick (10s)
      const aPromise = withStorageLock(key, async () => {
        await sleep(10500);
      });

      // Let A acquire the lock
      await jest.advanceTimersByTimeAsync(100);
      expect(storageData.has(key)).toBe(true);

      // First heartbeat tick fires at 10s; its storage read is held in flight
      interceptNextGet = true;
      await jest.advanceTimersByTimeAsync(9950);
      expect(resumeHeartbeatRead).toBeDefined();

      // The critical section finishes while the heartbeat tick is still in
      // flight; release must not let the pending renewal write the lock back
      await jest.advanceTimersByTimeAsync(600);
      resumeHeartbeatRead!();
      await aPromise;

      // The lock must be gone, not resurrected by the stale heartbeat write
      expect(storageData.has(key)).toBe(false);

      // And another contender must be able to acquire it promptly
      let bRan = false;
      const bPromise = withStorageLock(key, async () => {
        bRan = true;
      });
      await jest.advanceTimersByTimeAsync(100);
      await bPromise;
      expect(bRan).toBe(true);
    } finally {
      jest.useRealTimers();
    }
  });

  test("stale heartbeat read must not clobber another tab's takeover", async () => {
    jest.useFakeTimers();
    try {
      const key = "lock-stale-takeover-test";

      // Storage whose next getItem can be held in flight: the value is read
      // immediately (a snapshot still showing OUR lock) but the promise only
      // resolves later — after the lock has gone stale and another tab has
      // legitimately taken it over. The pending heartbeat renewal must then
      // NOT write, or it would overwrite the new holder and let both tabs
      // run their critical sections concurrently
      let interceptNextGet = false;
      let resumeHeartbeatRead: (() => void) | undefined;
      const gatedStorage = {
        getItem: (k: string): Promise<string | null> => {
          if (interceptNextGet) {
            interceptNextGet = false;
            const valueAtReadTime = storageData.get(k) ?? null;
            return new Promise((resolve) => {
              resumeHeartbeatRead = () => resolve(valueAtReadTime);
            });
          }
          return Promise.resolve(storageData.get(k) ?? null);
        },
        setItem: mockStorage.setItem,
        removeItem: mockStorage.removeItem,
      };
      configure({
        clientId: "testClient",
        cognitoIdpEndpoint: "us-west-2",
        storage: gatedStorage,
      });

      // Critical section (45s) outlives the stale-lock timeout (30s)
      const aPromise = withStorageLock(key, async () => {
        await sleep(45000);
      });

      // Let A acquire the lock
      await jest.advanceTimersByTimeAsync(100);
      expect(storageData.has(key)).toBe(true);

      // First heartbeat tick fires at 10s; its storage read is held in
      // flight (subsequent ticks queue behind it on the renewal chain), so
      // the lock timestamp is never renewed and the lock goes stale
      interceptNextGet = true;
      await jest.advanceTimersByTimeAsync(9950);
      expect(resumeHeartbeatRead).toBeDefined();

      // 31s in: the lock is now stale; tab B legitimately takes it over
      await jest.advanceTimersByTimeAsync(21000);
      const lockB = JSON.stringify({ id: "tab-B", timestamp: Date.now() });
      storageData.set(key, lockB);

      // The gated heartbeat read now resolves with the stale snapshot that
      // still shows A's id; the renewal must stand down instead of writing
      resumeHeartbeatRead!();
      await jest.advanceTimersByTimeAsync(50);
      expect(storageData.get(key)).toBe(lockB);

      // Later heartbeat ticks must not write either
      await jest.advanceTimersByTimeAsync(12000);
      expect(storageData.get(key)).toBe(lockB);

      // A's critical section ends; release must leave B's lock alone
      await jest.advanceTimersByTimeAsync(3000);
      await aPromise;
      expect(storageData.get(key)).toBe(lockB);
    } finally {
      jest.useRealTimers();
    }
  });

  test("heartbeat must detect a competing write via post-write verify and stand down", async () => {
    jest.useFakeTimers();
    try {
      const key = "lock-heartbeat-verify-test";

      // Storage that lets the renewal's pre-write read pass through, then
      // holds the post-write VERIFY read in flight; it resolves with the
      // value present at resume time, like a slow read completing after a
      // competing tab's write has landed
      let gateArmed = false;
      let readsToPassThrough = 0;
      let resumeVerifyRead: (() => void) | undefined;
      const gatedStorage = {
        getItem: (k: string): Promise<string | null> => {
          if (gateArmed) {
            if (readsToPassThrough > 0) {
              readsToPassThrough--;
            } else {
              gateArmed = false;
              return new Promise((resolve) => {
                resumeVerifyRead = () => resolve(storageData.get(k) ?? null);
              });
            }
          }
          return Promise.resolve(storageData.get(k) ?? null);
        },
        setItem: mockStorage.setItem,
        removeItem: mockStorage.removeItem,
      };
      configure({
        clientId: "testClient",
        cognitoIdpEndpoint: "us-west-2",
        storage: gatedStorage,
      });

      // Critical section ends shortly after the first heartbeat tick (10s)
      const aPromise = withStorageLock(key, async () => {
        await sleep(15000);
      });

      // Let A acquire the lock, then arm the gate for the first tick: the
      // renewal's own read passes through, its verify read is held
      await jest.advanceTimersByTimeAsync(100);
      expect(storageData.has(key)).toBe(true);
      gateArmed = true;
      readsToPassThrough = 1;

      // First heartbeat tick at 10s: reads (still ours), writes the renewed
      // lock, then starts the post-write verify, which is held in flight
      await jest.advanceTimersByTimeAsync(10100);
      expect(resumeVerifyRead).toBeDefined();

      // Tab B's write lands just after our renewal write (B judged the
      // pre-write value stale and went through write+verify itself)
      const lockB = JSON.stringify({ id: "tab-B", timestamp: Date.now() });
      storageData.set(key, lockB);

      // The verify read resolves showing B's lock: A must stand down and
      // stop renewing rather than keep acting as the holder
      resumeVerifyRead!();
      await jest.advanceTimersByTimeAsync(50);
      expect(storageData.get(key)).toBe(lockB);

      // A's critical section ends at 15s; release must leave B's lock alone
      await jest.advanceTimersByTimeAsync(5000);
      await aPromise;
      expect(storageData.get(key)).toBe(lockB);
    } finally {
      jest.useRealTimers();
    }
  });

  test("release must not remove a lock taken over by another tab", async () => {
    const key = "lock-takeover-test";
    const foreignLock = JSON.stringify({
      id: "other-tab",
      timestamp: Date.now(),
    });

    await withStorageLock(key, async () => {
      // Simulate another tab taking over the lock mid-critical-section
      storageData.set(key, foreignLock);
    });

    // The foreign lock must survive our release
    expect(storageData.get(key)).toBe(foreignLock);
  });
});
