import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

import {
  storeMasterKey,
  getMasterKey,
  deleteMasterKey,
  storeUnitKey,
  getUnitKey,
  deleteUnitKey,
  clearAllKeys,
  isStorageAvailable,
} from "@/lib/crypto/key-storage";
import { CryptoError } from "@/lib/crypto/types";

// Mock IndexedDB
interface MockIDBRequest {
  result: unknown;
  error: Error | null;
  onsuccess: (() => void) | null;
  onerror: (() => void) | null;
}

interface MockIDBTransaction {
  objectStore: ReturnType<typeof vi.fn>;
  oncomplete: (() => void) | null;
  onerror: (() => void) | null;
}

interface MockIDBObjectStore {
  put: ReturnType<typeof vi.fn>;
  get: ReturnType<typeof vi.fn>;
  delete: ReturnType<typeof vi.fn>;
  clear: ReturnType<typeof vi.fn>;
}

interface MockIDBDatabase {
  transaction: ReturnType<typeof vi.fn>;
  close: ReturnType<typeof vi.fn>;
  objectStoreNames: { contains: ReturnType<typeof vi.fn> };
  createObjectStore: ReturnType<typeof vi.fn>;
}

describe("Key Storage", () => {
  let mockDB: MockIDBDatabase;
  let mockTransaction: MockIDBTransaction;
  let mockObjectStore: MockIDBObjectStore;
  let mockRequest: MockIDBRequest;
  let originalIndexedDB: IDBFactory | undefined;

  beforeEach(() => {
    // Create mocks
    mockRequest = {
      result: null,
      error: null,
      onsuccess: null,
      onerror: null,
    };

    mockObjectStore = {
      put: vi.fn(() => mockRequest),
      get: vi.fn(() => mockRequest),
      delete: vi.fn(() => mockRequest),
      clear: vi.fn(() => mockRequest),
    };

    mockTransaction = {
      objectStore: vi.fn(() => mockObjectStore),
      oncomplete: null,
      onerror: null,
    };

    mockDB = {
      transaction: vi.fn(() => mockTransaction),
      close: vi.fn(),
      objectStoreNames: {
        contains: vi.fn(() => true),
      },
      createObjectStore: vi.fn(),
    };

    // Store original and mock indexedDB
    originalIndexedDB = globalThis.indexedDB;

    const mockOpenRequest: MockIDBRequest & {
      onupgradeneeded: ((event: unknown) => void) | null;
    } = {
      result: mockDB,
      error: null,
      onsuccess: null,
      onerror: null,
      onupgradeneeded: null,
    };

    Object.defineProperty(globalThis, "indexedDB", {
      value: {
        open: vi.fn(() => {
          // Simulate async open
          setTimeout(() => {
            if (mockOpenRequest.onsuccess) {
              mockOpenRequest.onsuccess();
            }
          }, 0);
          return mockOpenRequest;
        }),
      },
      configurable: true,
    });
  });

  afterEach(() => {
    if (originalIndexedDB) {
      Object.defineProperty(globalThis, "indexedDB", {
        value: originalIndexedDB,
        configurable: true,
      });
    }
  });

  describe("isStorageAvailable", () => {
    it("should return true when indexedDB is available", () => {
      expect(isStorageAvailable()).toBe(true);
    });

    it("should return false when indexedDB is undefined", () => {
      Object.defineProperty(globalThis, "indexedDB", {
        value: undefined,
        configurable: true,
      });

      expect(isStorageAvailable()).toBe(false);
    });
  });

  describe("storeMasterKey", () => {
    it("should store master key with userId and cachedAt", async () => {
      const mockKey = {
        type: "secret",
        extractable: false,
        algorithm: { name: "AES-GCM", length: 256 },
        usages: ["encrypt", "decrypt"],
      } as CryptoKey;

      // Simulate successful store
      setTimeout(() => {
        if (mockRequest.onsuccess) mockRequest.onsuccess();
        if (mockTransaction.oncomplete) mockTransaction.oncomplete();
      }, 10);

      await storeMasterKey("user-123", mockKey);

      expect(mockDB.transaction).toHaveBeenCalledWith(
        "master-keys",
        "readwrite"
      );
      expect(mockObjectStore.put).toHaveBeenCalled();

      const putArg = mockObjectStore.put.mock.calls[0]?.[0];
      expect(putArg?.userId).toBe("user-123");
      expect(putArg.key).toBe(mockKey);
      expect(typeof putArg.cachedAt).toBe("number");
    });

    it("should throw CryptoError on storage failure", async () => {
      const mockKey = {
        type: "secret",
        extractable: false,
        algorithm: { name: "AES-GCM", length: 256 },
        usages: ["encrypt", "decrypt"],
      } as CryptoKey;

      // Simulate failure
      setTimeout(() => {
        if (mockRequest.onerror) mockRequest.onerror();
      }, 10);

      await expect(storeMasterKey("user-123", mockKey)).rejects.toThrow(
        CryptoError
      );
    });
  });

  describe("getMasterKey", () => {
    it("should return key when found and not expired", async () => {
      const mockKey = {
        type: "secret",
        extractable: false,
        algorithm: { name: "AES-GCM", length: 256 },
        usages: ["encrypt", "decrypt"],
      } as CryptoKey;

      mockRequest.result = {
        userId: "user-123",
        key: mockKey,
        cachedAt: Date.now(), // Fresh key
      };

      setTimeout(() => {
        if (mockRequest.onsuccess) mockRequest.onsuccess();
        if (mockTransaction.oncomplete) mockTransaction.oncomplete();
      }, 10);

      const result = await getMasterKey("user-123");

      expect(result).toBe(mockKey);
      expect(mockObjectStore.get).toHaveBeenCalledWith("user-123");
    });

    it("should return null when key not found", async () => {
      mockRequest.result = null;

      setTimeout(() => {
        if (mockRequest.onsuccess) mockRequest.onsuccess();
        if (mockTransaction.oncomplete) mockTransaction.oncomplete();
      }, 10);

      const result = await getMasterKey("user-123");

      expect(result).toBeNull();
    });

    it("should return null and delete expired key", async () => {
      const mockKey = {
        type: "secret",
        extractable: false,
        algorithm: { name: "AES-GCM", length: 256 },
        usages: ["encrypt", "decrypt"],
      } as CryptoKey;

      // Key cached more than 24 hours ago
      const expiredCachedAt = Date.now() - 25 * 60 * 60 * 1000;
      mockRequest.result = {
        userId: "user-123",
        key: mockKey,
        cachedAt: expiredCachedAt,
      };

      setTimeout(() => {
        if (mockRequest.onsuccess) mockRequest.onsuccess();
        if (mockTransaction.oncomplete) mockTransaction.oncomplete();
      }, 10);

      const result = await getMasterKey("user-123");

      expect(result).toBeNull();
    });
  });

  describe("deleteMasterKey", () => {
    it("should delete key from store", async () => {
      setTimeout(() => {
        if (mockRequest.onsuccess) mockRequest.onsuccess();
        if (mockTransaction.oncomplete) mockTransaction.oncomplete();
      }, 10);

      await deleteMasterKey("user-123");

      expect(mockObjectStore.delete).toHaveBeenCalledWith("user-123");
    });
  });

  describe("storeUnitKey", () => {
    it("should store unit key with unitId and cachedAt", async () => {
      const mockKey = {
        type: "secret",
        extractable: false,
        algorithm: { name: "AES-GCM", length: 256 },
        usages: ["encrypt", "decrypt"],
      } as CryptoKey;

      setTimeout(() => {
        if (mockRequest.onsuccess) mockRequest.onsuccess();
        if (mockTransaction.oncomplete) mockTransaction.oncomplete();
      }, 10);

      await storeUnitKey(123, mockKey);

      expect(mockDB.transaction).toHaveBeenCalledWith("unit-keys", "readwrite");
      expect(mockObjectStore.put).toHaveBeenCalled();

      const putArg = mockObjectStore.put.mock.calls[0]?.[0];
      expect(putArg?.unitId).toBe(123);
      expect(putArg.key).toBe(mockKey);
      expect(typeof putArg.cachedAt).toBe("number");
    });
  });

  describe("getUnitKey", () => {
    it("should return key when found and not expired", async () => {
      const mockKey = {
        type: "secret",
        extractable: false,
        algorithm: { name: "AES-GCM", length: 256 },
        usages: ["encrypt", "decrypt"],
      } as CryptoKey;

      mockRequest.result = {
        unitId: 123,
        key: mockKey,
        cachedAt: Date.now(),
      };

      setTimeout(() => {
        if (mockRequest.onsuccess) mockRequest.onsuccess();
        if (mockTransaction.oncomplete) mockTransaction.oncomplete();
      }, 10);

      const result = await getUnitKey(123);

      expect(result).toBe(mockKey);
      expect(mockObjectStore.get).toHaveBeenCalledWith(123);
    });

    it("should return null when key not found", async () => {
      mockRequest.result = undefined;

      setTimeout(() => {
        if (mockRequest.onsuccess) mockRequest.onsuccess();
        if (mockTransaction.oncomplete) mockTransaction.oncomplete();
      }, 10);

      const result = await getUnitKey(123);

      expect(result).toBeNull();
    });
  });

  describe("deleteUnitKey", () => {
    it("should delete key from store", async () => {
      setTimeout(() => {
        if (mockRequest.onsuccess) mockRequest.onsuccess();
        if (mockTransaction.oncomplete) mockTransaction.oncomplete();
      }, 10);

      await deleteUnitKey(123);

      expect(mockObjectStore.delete).toHaveBeenCalledWith(123);
    });
  });

  describe("clearAllKeys", () => {
    it("should clear both stores", async () => {
      // Create separate requests for each clear operation
      const mockRequest1: MockIDBRequest = {
        result: null,
        error: null,
        onsuccess: null,
        onerror: null,
      };
      const mockRequest2: MockIDBRequest = {
        result: null,
        error: null,
        onsuccess: null,
        onerror: null,
      };

      let callCount = 0;
      mockObjectStore.clear = vi.fn(() => {
        const request = callCount === 0 ? mockRequest1 : mockRequest2;
        callCount++;
        // Trigger success immediately
        setTimeout(() => {
          if (request.onsuccess) request.onsuccess();
        }, 0);
        return request;
      });

      await clearAllKeys();

      // Should be called for both stores
      expect(mockDB.transaction).toHaveBeenCalled();
    });
  });
});
