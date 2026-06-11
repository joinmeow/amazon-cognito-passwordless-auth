/**
 * Unit tests for the setTimeoutWallClock timer primitive.
 *
 * Uses Jest's modern fake timers, where:
 * - jest.advanceTimersByTime(ms) advances both timers and Date.now()
 *   (normal passage of time)
 * - jest.setSystemTime(t) jumps Date.now() while preserving the relative
 *   remaining delay of pending timers — which models how browsers handle
 *   system sleep: setTimeout time spent sleeping is not (reliably) credited
 */

// Use the real implementation (client/__tests__/setup.ts mocks it globally)
jest.unmock("../client/util.js");

import { setTimeoutWallClock } from "../client/util.js";

const CHUNK_MS = 30 * 1000; // matches WALL_CLOCK_TIMEOUT_CHUNK_MS in client/util.ts
const FINAL_POLL_MS = 1000; // matches WALL_CLOCK_FINAL_POLL_MS in client/util.ts

describe("setTimeoutWallClock", () => {
  beforeEach(() => {
    jest.useFakeTimers();
  });

  afterEach(() => {
    jest.useRealTimers();
  });

  test("fires at the deadline under normal timer progression (long delay)", () => {
    const cb = jest.fn();
    setTimeoutWallClock(cb, 45 * 60 * 1000);

    jest.advanceTimersByTime(45 * 60 * 1000 - 1);
    expect(cb).not.toHaveBeenCalled();

    jest.advanceTimersByTime(1);
    expect(cb).toHaveBeenCalledTimes(1);
  });

  test("fires at the deadline under normal timer progression (short delay)", () => {
    const cb = jest.fn();
    setTimeoutWallClock(cb, 5000);

    jest.advanceTimersByTime(4999);
    expect(cb).not.toHaveBeenCalled();

    jest.advanceTimersByTime(1);
    expect(cb).toHaveBeenCalledTimes(1);
  });

  test("fires within one chunk after wake when the deadline passed during device sleep", () => {
    const cb = jest.fn();
    setTimeoutWallClock(cb, 45 * 60 * 1000);

    // 10 minutes of normal operation
    jest.advanceTimersByTime(10 * 60 * 1000);
    expect(cb).not.toHaveBeenCalled();

    // Device sleeps for 8 hours: wall clock jumps way past the deadline,
    // but pending setTimeouts get no credit for the time spent sleeping
    jest.setSystemTime(Date.now() + 8 * 60 * 60 * 1000);
    expect(cb).not.toHaveBeenCalled();

    // After wake, the currently pending chunk elapses (at most CHUNK_MS),
    // the wall clock is re-checked, and the overdue callback fires
    jest.advanceTimersByTime(CHUNK_MS);
    expect(cb).toHaveBeenCalledTimes(1);
  });

  test("fires within the poll interval after wake when the deadline passed during sleep on a short delay", () => {
    const cb = jest.fn();
    setTimeoutWallClock(cb, 10 * 1000);

    // 2 seconds of normal operation
    jest.advanceTimersByTime(2 * 1000);
    expect(cb).not.toHaveBeenCalled();

    // Device sleeps for an hour: wall clock jumps way past the deadline,
    // but pending setTimeouts get no credit for the time spent sleeping
    jest.setSystemTime(Date.now() + 60 * 60 * 1000);
    expect(cb).not.toHaveBeenCalled();

    // After wake, the overdue callback fires within one poll interval —
    // NOT only after the full remaining 8 seconds of one uncredited timer
    jest.advanceTimersByTime(FINAL_POLL_MS);
    expect(cb).toHaveBeenCalledTimes(1);
  });

  test("fires within the poll interval after wake when sleep hits the final stretch of a long delay", () => {
    const cb = jest.fn();
    setTimeoutWallClock(cb, 45 * 60 * 1000);

    // Normal operation until 15 seconds before the deadline
    jest.advanceTimersByTime(45 * 60 * 1000 - 15 * 1000);
    expect(cb).not.toHaveBeenCalled();

    // Device sleeps past the deadline during the final stretch
    jest.setSystemTime(Date.now() + 60 * 60 * 1000);
    expect(cb).not.toHaveBeenCalled();

    // After wake, the overdue callback fires within one poll interval
    jest.advanceTimersByTime(FINAL_POLL_MS);
    expect(cb).toHaveBeenCalledTimes(1);
  });

  test("does not fire early if the wall clock jumps but the deadline has not passed", () => {
    const cb = jest.fn();
    setTimeoutWallClock(cb, 45 * 60 * 1000);

    // Device sleeps for 10 minutes: deadline (45 min) not reached yet
    jest.setSystemTime(Date.now() + 10 * 60 * 1000);
    jest.advanceTimersByTime(CHUNK_MS);
    expect(cb).not.toHaveBeenCalled();

    // Remaining wall-clock time elapses normally
    jest.advanceTimersByTime(35 * 60 * 1000 - CHUNK_MS);
    expect(cb).toHaveBeenCalledTimes(1);
  });

  test("cancellation between chunks clears the pending chunk timer", () => {
    const cb = jest.fn();
    const cancel = setTimeoutWallClock(cb, 5 * 60 * 1000);

    // Advance a few chunks in, then cancel
    jest.advanceTimersByTime(2 * 60 * 1000);
    cancel();

    // The currently pending chunk timer must be cleared
    expect(jest.getTimerCount()).toBe(0);

    jest.advanceTimersByTime(10 * 60 * 1000);
    expect(cb).not.toHaveBeenCalled();
  });

  test("cancellation also works after device sleep, before the chunk fires", () => {
    const cb = jest.fn();
    const cancel = setTimeoutWallClock(cb, 45 * 60 * 1000);

    jest.advanceTimersByTime(10 * 60 * 1000);

    // Sleep past the deadline, then cancel before the pending chunk fires
    jest.setSystemTime(Date.now() + 8 * 60 * 60 * 1000);
    cancel();

    jest.advanceTimersByTime(60 * 60 * 1000);
    expect(cb).not.toHaveBeenCalled();
  });

  test("fires on the next tick for a zero (or negative) delay", () => {
    const cb = jest.fn();
    setTimeoutWallClock(cb, 0);

    // Not synchronously...
    expect(cb).not.toHaveBeenCalled();

    // ...but on the next timer tick
    jest.advanceTimersByTime(0);
    expect(cb).toHaveBeenCalledTimes(1);
  });
});
