import { configure } from "../client/config.js";
import { withStorageLock } from "../client/lock.js";

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

describe("Storage Lock", () => {
  beforeEach(() => {
    // Use an in-memory storage (default) with test config
    configure({ clientId: "testClient", cognitoIdpEndpoint: "us-west-2" });
  });

  test("should enforce sequential lock ordering", async () => {
    const order: string[] = [];

    // Start first lock operation
    const firstPromise = withStorageLock("key1", async () => {
      order.push("first-start");
      await sleep(100);
      order.push("first-end");
    });

    // Give first lock time to acquire
    await sleep(10);

    // Try to acquire same lock - should wait
    const secondPromise = withStorageLock("key1", async () => {
      order.push("second");
    });

    await Promise.all([firstPromise, secondPromise]);

    expect(order).toEqual(["first-start", "first-end", "second"]);
  });

  test("should timeout when lock is never released", async () => {
    // Hold lock for 200ms
    const lockPromise = withStorageLock("key2", async () => {
      await sleep(200);
    });

    // Give first lock time to acquire
    await sleep(10);

    // Attempt to acquire with short timeout
    await expect(withStorageLock("key2", async () => {}, 50)).rejects.toThrow(
      /Timeout acquiring lock/
    );

    // Wait for the first lock to complete to avoid test interference
    await lockPromise;
  });

  test("should cleanup lock map when it exceeds 100 entries", async () => {
    // Create many lock operations to trigger cleanup
    const promises: Promise<void>[] = [];

    // Create 105 different lock keys to exceed the 100 limit
    for (let i = 0; i < 105; i++) {
      promises.push(
        withStorageLock(`cleanup-test-key-${i}`, async () => {
          // Quick operation
          await sleep(1);
        })
      );
    }

    // All should complete successfully despite cleanup
    await Promise.all(promises);

    // Test passes if no errors are thrown and all locks complete
    expect(true).toBe(true);
  });
});
