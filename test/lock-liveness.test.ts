import { configure } from "../client/config.js";
import { withStorageLock, LockTimeoutError } from "../client/lock.js";

const KEY = "Passwordless.testClient.testuser.refreshLock";

function createMemoryStorage() {
  const store = new Map<string, string>();
  return {
    getItem: (key: string) => store.get(key) ?? null,
    setItem: (key: string, value: string) => {
      store.set(key, value);
    },
    removeItem: (key: string) => {
      store.delete(key);
    },
    _store: store,
  };
}

let storage: ReturnType<typeof createMemoryStorage>;

// Drive a promise to settlement under fake timers by advancing time in
// steps (the lock's poll loops, jitters and heartbeats all use timers)
async function drive<T>(
  promise: Promise<T>,
  maxSteps: number,
  stepMs: number
): Promise<{ settled: boolean; value?: T; error?: unknown }> {
  const outcome: { settled: boolean; value?: T; error?: unknown } = {
    settled: false,
  };
  promise.then(
    (value) => {
      outcome.settled = true;
      outcome.value = value;
    },
    (error) => {
      outcome.settled = true;
      outcome.error = error;
    }
  );
  for (let i = 0; i < maxSteps && !outcome.settled; i++) {
    await jest.advanceTimersByTimeAsync(stepMs);
  }
  return outcome;
}

beforeEach(() => {
  jest.useFakeTimers();
  storage = createMemoryStorage();
  configure({
    clientId: "testClient",
    cognitoIdpEndpoint: "us-west-2",
    storage,
  });
});

afterEach(() => {
  jest.useRealTimers();
});

describe("lock liveness", () => {
  test("a waiter outlasts an orphaned lock: default timeout exceeds the stale threshold", async () => {
    // A page killed mid-critical-section leaves its lock behind with a
    // fresh timestamp and no process to renew or release it. The waiter's
    // default timeout must be long enough for the orphan to go stale
    // (30s) and be taken over — previously the default was 15s, so every
    // waiter starting within ~15s of the orphan's last heartbeat was
    // GUARANTEED a LockTimeoutError.
    storage.setItem(
      KEY,
      JSON.stringify({ id: "orphaned-by-dead-page", timestamp: Date.now() })
    );

    const outcome = await drive(
      withStorageLock(KEY, async () => "acquired"),
      60,
      1000
    );

    expect(outcome.settled).toBe(true);
    expect(outcome.error).toBeUndefined();
    expect(outcome.value).toBe("acquired");
  });

  test("heartbeat renewals are capped: a hung critical section loses the lock to a takeover", async () => {
    // A refresh fetch stuck on a dead connection used to renew the lock's
    // heartbeat forever, making the lock unstealable — no other tab could
    // refresh or sign out. Renewals now stop after MAX_LOCK_HOLD_MS, the
    // lock goes stale, and a contender takes over.
    let releaseHang!: () => void;
    const hang = new Promise<void>((resolve) => {
      releaseHang = resolve;
    });
    const holderOutcome: { value?: string } = {};
    void withStorageLock(KEY, async () => {
      await hang;
      return "holder-finished";
    }).then((v) => {
      holderOutcome.value = v;
    });

    // Let the holder acquire (poll + ownership-verify jitter)
    await jest.advanceTimersByTimeAsync(100);
    expect(storage.getItem(KEY)).toBeTruthy();

    // Advance past the hold cap plus one heartbeat interval: renewals stop
    await jest.advanceTimersByTimeAsync(135_000);
    // ... then past the stale threshold with no renewals landing
    await jest.advanceTimersByTimeAsync(31_000);

    // A contender must now be able to clear the stale lock and acquire
    const takeover = await drive(
      withStorageLock(KEY, async () => "taken-over"),
      30,
      1000
    );
    expect(takeover.settled).toBe(true);
    expect(takeover.error).toBeUndefined();
    expect(takeover.value).toBe("taken-over");

    // The hung holder eventually finishes; it must not clobber anything
    // (its release only removes the lock if it still owns it)
    releaseHang();
    await jest.advanceTimersByTimeAsync(1000);
    expect(holderOutcome.value).toBe("holder-finished");
  });

  test("a healthy long critical section is still protected by the heartbeat within the cap", async () => {
    // Sanity check that the cap did not break the heartbeat's purpose: a
    // legitimate 60s critical section (well under the cap) keeps the lock
    // fresh, and a contender waits its full timeout rather than stealing.
    let releaseHang!: () => void;
    const hang = new Promise<void>((resolve) => {
      releaseHang = resolve;
    });
    const holder = withStorageLock(KEY, async () => {
      await hang;
      return "ok";
    });
    await jest.advanceTimersByTimeAsync(100);

    // Contender with a short explicit timeout starts at t≈0 of the hold;
    // the holder renews every 10s, so the lock never goes stale and the
    // contender must time out
    const contender = await drive(
      withStorageLock(KEY, async () => "stolen", 20_000),
      30,
      1000
    );
    expect(contender.settled).toBe(true);
    expect(contender.error).toBeInstanceOf(LockTimeoutError);

    releaseHang();
    await jest.advanceTimersByTimeAsync(1000);
    await expect(holder).resolves.toBe("ok");
    // Released cleanly
    expect(storage.getItem(KEY)).toBeNull();
  });
});
