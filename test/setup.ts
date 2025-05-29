// Jest setup file
// Mock browser globals that might be needed
Object.defineProperty(globalThis, 'localStorage', {
  value: {
    store: new Map<string, string>(),
    getItem(key: string) {
      return this.store.get(key) || null;
    },
    setItem(key: string, value: string) {
      this.store.set(key, value);
    },
    removeItem(key: string) {
      this.store.delete(key);
    },
    clear() {
      this.store.clear();
    },
  },
  writable: true,
});

// Mock fetch for tests
Object.defineProperty(globalThis, 'fetch', {
  value: jest.fn(() =>
    Promise.resolve({
      ok: true,
      json: () => Promise.resolve({}),
    })
  ),
  writable: true,
});

// Mock TextDecoder
Object.defineProperty(globalThis, 'TextDecoder', {
  value: class TextDecoder {
    decode(buffer: ArrayBuffer | Uint8Array): string {
      const uint8Array = buffer instanceof ArrayBuffer ? new Uint8Array(buffer) : buffer;
      return String.fromCharCode(...Array.from(uint8Array));
    }
  },
  writable: true,
});

// jsdom already provides document, just ensure it has the properties we need
if (typeof document !== 'undefined') {
  Object.defineProperty(document, 'hidden', {
    value: false,
    writable: true,
  });
}

// Extend Jest timeout for async operations
jest.setTimeout(10000); 