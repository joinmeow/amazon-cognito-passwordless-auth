import { configure } from "../client/config.js";
import { withStorageLock } from "../client/lock.js";

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

describe('Storage Lock', () => {
  beforeEach(() => {
    // Use an in-memory storage (default) with test config
    configure({ clientId: "testClient", cognitoIdpEndpoint: "us-west-2" });
  });

  test('should enforce sequential lock ordering', async () => {
    const order: string[] = [];
    await Promise.all([
      withStorageLock("key1", async () => {
        order.push("first-start");
        await sleep(100);
        order.push("first-end");
      }),
      withStorageLock("key1", async () => {
        order.push("second");
      }),
    ]);
    
    expect(order).toEqual(["first-start", "first-end", "second"]);
  });

  test('should timeout when lock is never released', async () => {
    // Hold lock for 200ms
    const lockPromise = withStorageLock("key2", async () => {
      await sleep(200);
    });
    
    // Attempt to acquire with short timeout
    await expect(
      withStorageLock("key2", async () => {}, 50)
    ).rejects.toThrow(/Timeout acquiring lock/);
    
    // Wait for the first lock to complete to avoid test interference
    await lockPromise;
  });
}); 