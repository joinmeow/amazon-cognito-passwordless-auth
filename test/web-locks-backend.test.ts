import { configure } from "../client/config.js";
import {
  withLock,
  LockTimeoutError,
  isLockTimeoutError,
  activeLockBackend,
} from "../client/lock.js";

// Phase 1: withLock uses the Web Locks API when available (browser-owned,
// auto-released on tab death) and falls back to the storage lock otherwise.
// jsdom has no navigator.locks, so we install a faithful in-memory mock to
// exercise the Web Locks path; without it, withLock takes the storage fallback.

interface MockLockOptions {
  mode?: "exclusive" | "shared";
  signal?: AbortSignal;
  ifAvailable?: boolean;
}

// Minimal, spec-faithful LockManager: exclusive requests on a name serialize;
// a pending (queued) request rejects with AbortError when its signal aborts;
// aborting after the grant has no effect; the held lock releases when the
// callback promise settles (resolve OR reject).
function createWebLocksMock() {
  const entries = new Map<
    string,
    { held: boolean; queue: Array<() => void> }
  >();
  const getEntry = (name: string) => {
    let e = entries.get(name);
    if (!e) {
      e = { held: false, queue: [] };
      entries.set(name, e);
    }
    return e;
  };
  const request = jest.fn(
    (
      name: string,
      options: MockLockOptions,
      callback: (lock: unknown) => Promise<unknown>
    ) =>
      new Promise((resolve, reject) => {
        const entry = getEntry(name);
        const signal = options?.signal;
        let granted = false;

        // Spec: with ifAvailable, a held lock invokes the callback with null
        // instead of queueing the request.
        if (options?.ifAvailable && entry.held) {
          Promise.resolve()
            .then(() => callback(null))
            .then(resolve, reject);
          return;
        }

        const run = async () => {
          granted = true;
          entry.held = true;
          signal?.removeEventListener("abort", onAbort);
          try {
            resolve(
              await callback({ name, mode: options?.mode ?? "exclusive" })
            );
          } catch (err) {
            reject(err);
          } finally {
            entry.held = false;
            const next = entry.queue.shift();
            if (next) next();
          }
        };
        const onAbort = () => {
          if (granted) return;
          const i = entry.queue.indexOf(run);
          if (i >= 0) entry.queue.splice(i, 1);
          reject(new DOMException("The operation was aborted", "AbortError"));
        };

        if (signal?.aborted) {
          reject(new DOMException("The operation was aborted", "AbortError"));
          return;
        }
        signal?.addEventListener("abort", onAbort, { once: true });

        if (!entry.held) {
          run();
        } else {
          entry.queue.push(run);
        }
      })
  );
  return { request };
}

let mock: ReturnType<typeof createWebLocksMock> | undefined;
function installWebLocksMock() {
  mock = createWebLocksMock();
  Object.defineProperty(globalThis.navigator, "locks", {
    value: mock,
    configurable: true,
    writable: true,
  });
  return mock;
}
function uninstallWebLocksMock() {
  if (mock && "locks" in globalThis.navigator) {
    delete (globalThis.navigator as { locks?: unknown }).locks;
  }
  mock = undefined;
}

function createEnumerableStorage() {
  const backing = new Map<string, string>();
  return {
    backing,
    storage: {
      getItem: (k: string) => backing.get(k) ?? null,
      setItem: (k: string, v: string) => {
        backing.set(k, v);
      },
      removeItem: (k: string) => {
        backing.delete(k);
      },
    },
  };
}

const LOCK_KEY = "Passwordless.testClient.testuser.refreshLock";

describe("withLock backend selection", () => {
  afterEach(() => {
    uninstallWebLocksMock();
    jest.useRealTimers();
  });

  test("uses the Web Locks backend and writes NO storage lock record when available", async () => {
    const m = installWebLocksMock();
    const { backing, storage } = createEnumerableStorage();
    configure({
      clientId: "testClient",
      cognitoIdpEndpoint: "us-west-2",
      storage,
    });

    let sawLockRecordMidSection = false;
    const result = await withLock(LOCK_KEY, async () => {
      // The storage backend would have a record for LOCK_KEY here.
      sawLockRecordMidSection = backing.has(LOCK_KEY);
      return "done";
    });

    expect(result).toBe("done");
    expect(m.request).toHaveBeenCalledTimes(1);
    expect(m.request.mock.calls[0][0]).toBe(LOCK_KEY);
    expect(sawLockRecordMidSection).toBe(false);
    // No lingering storage lock record either.
    expect(backing.has(LOCK_KEY)).toBe(false);
  });

  test("falls back to the storage lock when Web Locks is unavailable", async () => {
    // No mock installed → navigator.locks absent → storage backend.
    const { backing, storage } = createEnumerableStorage();
    configure({
      clientId: "testClient",
      cognitoIdpEndpoint: "us-west-2",
      storage,
    });

    let sawStorageRecord = false;
    await withLock(LOCK_KEY, async () => {
      sawStorageRecord = backing.has(LOCK_KEY);
    });

    // The storage backend writes (and then removes) a lock record.
    expect(sawStorageRecord).toBe(true);
    expect(backing.has(LOCK_KEY)).toBe(false);
  });

  test("serializes two exclusive contenders on the same key", async () => {
    installWebLocksMock();
    configure({ clientId: "testClient", cognitoIdpEndpoint: "us-west-2" });

    let active = 0;
    let maxActive = 0;
    const task = async () => {
      active++;
      maxActive = Math.max(maxActive, active);
      await new Promise((r) => setTimeout(r, 20));
      active--;
    };

    await Promise.all([withLock(LOCK_KEY, task), withLock(LOCK_KEY, task)]);
    expect(maxActive).toBe(1);
  });

  test("maps the acquisition deadline to LockTimeoutError (pending request only)", async () => {
    jest.useFakeTimers();
    installWebLocksMock();
    configure({ clientId: "testClient", cognitoIdpEndpoint: "us-west-2" });

    let releaseHolder!: () => void;
    const holderGate = new Promise<void>((r) => {
      releaseHolder = r;
    });
    const holder = withLock(LOCK_KEY, async () => {
      await holderGate;
    });
    await Promise.resolve(); // let the holder acquire

    let waiterErr: unknown;
    const waiter = withLock(LOCK_KEY, async () => "never", 1000).catch((e) => {
      waiterErr = e;
    });

    await jest.advanceTimersByTimeAsync(1000);
    await waiter;
    expect(waiterErr).toBeInstanceOf(LockTimeoutError);

    releaseHolder();
    await holder;
  });

  test("propagates a caller abort as AbortError, not LockTimeoutError", async () => {
    installWebLocksMock();
    configure({ clientId: "testClient", cognitoIdpEndpoint: "us-west-2" });

    let releaseHolder!: () => void;
    const holderGate = new Promise<void>((r) => {
      releaseHolder = r;
    });
    const holder = withLock(LOCK_KEY, async () => {
      await holderGate;
    });
    await Promise.resolve();

    const abort = new AbortController();
    let waiterErr: unknown;
    const waiter = withLock(
      LOCK_KEY,
      async () => "never",
      60000,
      abort.signal
    ).catch((e) => {
      waiterErr = e;
    });
    abort.abort();
    await waiter;

    expect(waiterErr).toBeInstanceOf(DOMException);
    expect((waiterErr as DOMException).name).toBe("AbortError");
    expect(waiterErr).not.toBeInstanceOf(LockTimeoutError);

    releaseHolder();
    await holder;
  });

  test("activeLockBackend reports which backend withLock will use", () => {
    // No mock → storage fallback (jsdom has no navigator.locks).
    expect(activeLockBackend()).toBe("storage");
    installWebLocksMock();
    expect(activeLockBackend()).toBe("web-locks");
  });

  test("releases the lock when the callback rejects, so the next contender can acquire", async () => {
    installWebLocksMock();
    configure({ clientId: "testClient", cognitoIdpEndpoint: "us-west-2" });

    await expect(
      withLock(LOCK_KEY, async () => {
        throw new Error("boom");
      })
    ).rejects.toThrow("boom");

    // The lock must have been released despite the throw.
    let ran = false;
    await withLock(LOCK_KEY, async () => {
      ran = true;
    });
    expect(ran).toBe(true);
  });

  test("timeoutMs 0 (try-immediate) acquires a free lock and runs the callback", async () => {
    const m = installWebLocksMock();
    configure({ clientId: "testClient", cognitoIdpEndpoint: "us-west-2" });

    const result = await withLock(LOCK_KEY, async () => "ran", 0);

    expect(result).toBe("ran");
    // ifAvailable was requested — a free lock is granted, never queued.
    expect(m.request.mock.calls[0][1]).toMatchObject({ ifAvailable: true });
  });

  test("timeoutMs 0 (try-immediate) throws LockTimeoutError at once when the lock is held, without queueing", async () => {
    installWebLocksMock();
    configure({ clientId: "testClient", cognitoIdpEndpoint: "us-west-2" });

    let releaseHolder!: () => void;
    const holderGate = new Promise<void>((r) => {
      releaseHolder = r;
    });
    const holder = withLock(LOCK_KEY, async () => {
      await holderGate;
      return "holder-done";
    });
    await Promise.resolve(); // let the holder acquire

    // No timers are driven: the rejection must be immediate, not a timeout.
    let ran = false;
    const err = await withLock(
      LOCK_KEY,
      async () => {
        ran = true;
      },
      0
    ).catch((e: unknown) => e);

    expect(isLockTimeoutError(err)).toBe(true);
    expect(ran).toBe(false);

    // The holder was never disturbed by the try-immediate attempt.
    releaseHolder();
    await expect(holder).resolves.toBe("holder-done");
  });

  test("isLockTimeoutError recognizes an instance from a duplicated module copy (where instanceof fails)", () => {
    // Simulate a bundler shipping two copies of lock.ts: the "foreign" copy's
    // LockTimeoutError shares the shape (name + isLockTimeout marker) but not
    // the prototype, so instanceof is false. The type guard must still match.
    const foreign = Object.assign(
      new Error("Timeout acquiring lock 'k' after 5ms"),
      { name: "LockTimeoutError", isLockTimeout: true }
    );

    expect(foreign instanceof LockTimeoutError).toBe(false);
    expect(isLockTimeoutError(foreign)).toBe(true);

    // And it stays a guard, not a name-sniffer: plain errors don't match.
    expect(isLockTimeoutError(new Error("Timeout acquiring lock"))).toBe(false);
    expect(isLockTimeoutError(undefined)).toBe(false);
  });

  test("falls back to the storage lock when request() rejects with SecurityError before any grant (opaque origin)", async () => {
    // A sandboxed iframe without allow-same-origin exposes navigator.locks
    // but rejects every request() with SecurityError. The critical section
    // has not run, so withLock must retry it on the storage backend rather
    // than surface a baffling SecurityError.
    const securityMock = {
      request: jest.fn(() =>
        Promise.reject(
          new DOMException("The request was denied", "SecurityError")
        )
      ),
    };
    Object.defineProperty(globalThis.navigator, "locks", {
      value: securityMock,
      configurable: true,
      writable: true,
    });
    mock = securityMock as unknown as ReturnType<typeof createWebLocksMock>;
    const { backing, storage } = createEnumerableStorage();
    configure({
      clientId: "testClient",
      cognitoIdpEndpoint: "us-west-2",
      storage,
    });

    let sawStorageRecord = false;
    const result = await withLock(LOCK_KEY, async () => {
      sawStorageRecord = backing.has(LOCK_KEY);
      return "via-storage";
    });

    expect(result).toBe("via-storage");
    expect(securityMock.request).toHaveBeenCalledTimes(1);
    // fn ran exactly once, under the STORAGE lock.
    expect(sawStorageRecord).toBe(true);
    expect(backing.has(LOCK_KEY)).toBe(false);
  });

  test("a SecurityError thrown INSIDE the critical section propagates (no storage retry, fn must not run twice)", async () => {
    installWebLocksMock();
    const { backing, storage } = createEnumerableStorage();
    configure({
      clientId: "testClient",
      cognitoIdpEndpoint: "us-west-2",
      storage,
    });

    let runs = 0;
    const err = await withLock(LOCK_KEY, async () => {
      runs++;
      throw new DOMException("thrown by fn", "SecurityError");
    }).catch((e: unknown) => e);

    expect(runs).toBe(1);
    expect(err).toBeInstanceOf(DOMException);
    expect((err as DOMException).name).toBe("SecurityError");
    // Never re-ran on the storage backend.
    expect(backing.has(LOCK_KEY)).toBe(false);
  });

  test("an AbortError thrown INSIDE the critical section is not reported as a lock timeout", async () => {
    // The acquisition deadline can fire in the gap between the browser granting
    // the lock and our callback clearing the timer (the browser grants, then
    // queues a task to invoke the callback). Aborting after the grant has no
    // effect on the held lock per spec — but the deadline flag is set. If fn()
    // then throws its own AbortError (e.g. an aborted fetch inside the critical
    // section), it must propagate unchanged rather than be translated into a
    // LockTimeoutError the caller would treat as "another tab is refreshing".
    const grantThenDelayCallback = {
      request: jest.fn(
        (
          _name: string,
          _options: MockLockOptions,
          callback: (lock: unknown) => Promise<unknown>
        ) =>
          // Lock is granted here; the callback runs a macrotask later, which is
          // the window the acquisition timer can fire in.
          new Promise((resolve, reject) => {
            setTimeout(() => {
              void callback({}).then(resolve, reject);
            }, 50);
          })
      ),
    };
    Object.defineProperty(globalThis.navigator, "locks", {
      value: grantThenDelayCallback,
      configurable: true,
      writable: true,
    });
    mock = grantThenDelayCallback as unknown as ReturnType<
      typeof createWebLocksMock
    >;
    configure({ clientId: "testClient", cognitoIdpEndpoint: "us-west-2" });

    // 10ms deadline expires during the 50ms grant→callback gap.
    const err = await withLock(
      LOCK_KEY,
      async () => {
        throw new DOMException("The operation was aborted", "AbortError");
      },
      10
    ).catch((e: unknown) => e);

    expect(err).toBeInstanceOf(DOMException);
    expect((err as DOMException).name).toBe("AbortError");
    expect(err).not.toBeInstanceOf(LockTimeoutError);
  });
});
