/**
 * Key Storage Module
 * Manages encryption keys in IndexedDB for session persistence
 */

import { logger } from "@/lib/logger";

import { CryptoError, CryptoErrorType } from "./types";

import type { StoredKeyEntry } from "./types";

const DB_NAME = "helvety-crypto";
const DB_VERSION = 1;
const MASTER_KEY_STORE = "master-keys";
const UNIT_KEY_STORE = "unit-keys";

/** Cache duration for keys (24 hours) */
const KEY_CACHE_DURATION = 24 * 60 * 60 * 1000;

/**
 * Open the IndexedDB database
 */
async function openDatabase(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, DB_VERSION);

    request.onerror = () => {
      reject(
        new CryptoError(
          CryptoErrorType.STORAGE_ERROR,
          "Failed to open key storage database"
        )
      );
    };

    request.onsuccess = () => {
      resolve(request.result);
    };

    request.onupgradeneeded = (event) => {
      const db = (event.target as IDBOpenDBRequest).result;

      // Store for the master key (keyed by user ID)
      if (!db.objectStoreNames.contains(MASTER_KEY_STORE)) {
        db.createObjectStore(MASTER_KEY_STORE, { keyPath: "userId" });
      }

      // Store for unit keys (keyed by unitId)
      if (!db.objectStoreNames.contains(UNIT_KEY_STORE)) {
        db.createObjectStore(UNIT_KEY_STORE, { keyPath: "unitId" });
      }
    };
  });
}

/**
 * Store the master key in IndexedDB
 * Note: CryptoKey objects can be stored directly in IndexedDB
 *
 * @param userId - The user's ID
 * @param key - The master CryptoKey
 */
export async function storeMasterKey(
  userId: string,
  key: CryptoKey
): Promise<void> {
  try {
    const db = await openDatabase();

    return new Promise((resolve, reject) => {
      const transaction = db.transaction(MASTER_KEY_STORE, "readwrite");
      const store = transaction.objectStore(MASTER_KEY_STORE);

      const request = store.put({
        userId,
        key,
        cachedAt: Date.now(),
      });

      request.onerror = () => {
        reject(
          new CryptoError(
            CryptoErrorType.STORAGE_ERROR,
            "Failed to store master key"
          )
        );
      };

      request.onsuccess = () => {
        resolve();
      };

      transaction.oncomplete = () => {
        db.close();
      };
    });
  } catch (error) {
    if (error instanceof CryptoError) throw error;
    throw new CryptoError(
      CryptoErrorType.STORAGE_ERROR,
      "Failed to store master key",
      error instanceof Error ? error : undefined
    );
  }
}

/**
 * Retrieve the master key from IndexedDB
 *
 * @param userId - The user's ID
 * @returns The master key if found and not expired, null otherwise
 */
export async function getMasterKey(userId: string): Promise<CryptoKey | null> {
  try {
    const db = await openDatabase();

    return new Promise((resolve, reject) => {
      const transaction = db.transaction(MASTER_KEY_STORE, "readonly");
      const store = transaction.objectStore(MASTER_KEY_STORE);

      const request = store.get(userId);

      request.onerror = () => {
        reject(
          new CryptoError(
            CryptoErrorType.STORAGE_ERROR,
            "Failed to retrieve master key"
          )
        );
      };

      request.onsuccess = () => {
        const result = request.result;
        if (!result) {
          resolve(null);
          return;
        }

        // Check if key has expired
        if (Date.now() - result.cachedAt > KEY_CACHE_DURATION) {
          // Key expired, clean it up
          deleteMasterKey(userId).catch((err) =>
            logger.error("Failed to delete expired master key:", err)
          );
          resolve(null);
          return;
        }

        resolve(result.key);
      };

      transaction.oncomplete = () => {
        db.close();
      };
    });
  } catch (error) {
    if (error instanceof CryptoError) throw error;
    return null;
  }
}

/**
 * Delete the master key from IndexedDB
 * Call this on logout or when the user wants to lock encryption
 */
export async function deleteMasterKey(userId: string): Promise<void> {
  try {
    const db = await openDatabase();

    return new Promise((resolve, reject) => {
      const transaction = db.transaction(MASTER_KEY_STORE, "readwrite");
      const store = transaction.objectStore(MASTER_KEY_STORE);

      const request = store.delete(userId);

      request.onerror = () => {
        reject(
          new CryptoError(
            CryptoErrorType.STORAGE_ERROR,
            "Failed to delete master key"
          )
        );
      };

      request.onsuccess = () => {
        resolve();
      };

      transaction.oncomplete = () => {
        db.close();
      };
    });
  } catch (error) {
    // Silently fail on delete errors
    logger.error("Failed to delete master key:", error);
  }
}

/**
 * Store a unit key in IndexedDB
 */
export async function storeUnitKey(
  unitId: number,
  key: CryptoKey
): Promise<void> {
  try {
    const db = await openDatabase();

    return new Promise((resolve, reject) => {
      const transaction = db.transaction(UNIT_KEY_STORE, "readwrite");
      const store = transaction.objectStore(UNIT_KEY_STORE);

      const entry: StoredKeyEntry = {
        unitId,
        key,
        cachedAt: Date.now(),
      };

      const request = store.put(entry);

      request.onerror = () => {
        reject(
          new CryptoError(
            CryptoErrorType.STORAGE_ERROR,
            "Failed to store unit key"
          )
        );
      };

      request.onsuccess = () => {
        resolve();
      };

      transaction.oncomplete = () => {
        db.close();
      };
    });
  } catch (error) {
    if (error instanceof CryptoError) throw error;
    throw new CryptoError(
      CryptoErrorType.STORAGE_ERROR,
      "Failed to store unit key",
      error instanceof Error ? error : undefined
    );
  }
}

/**
 * Retrieve a unit key from IndexedDB
 */
export async function getUnitKey(unitId: number): Promise<CryptoKey | null> {
  try {
    const db = await openDatabase();

    return new Promise((resolve, reject) => {
      const transaction = db.transaction(UNIT_KEY_STORE, "readonly");
      const store = transaction.objectStore(UNIT_KEY_STORE);

      const request = store.get(unitId);

      request.onerror = () => {
        reject(
          new CryptoError(
            CryptoErrorType.STORAGE_ERROR,
            "Failed to retrieve unit key"
          )
        );
      };

      request.onsuccess = () => {
        const result = request.result as StoredKeyEntry | undefined;
        if (!result) {
          resolve(null);
          return;
        }

        // Check if key has expired
        if (Date.now() - result.cachedAt > KEY_CACHE_DURATION) {
          deleteUnitKey(unitId).catch((err) =>
            logger.error("Failed to delete expired unit key:", err)
          );
          resolve(null);
          return;
        }

        resolve(result.key);
      };

      transaction.oncomplete = () => {
        db.close();
      };
    });
  } catch {
    return null;
  }
}

/**
 * Delete a unit key from IndexedDB
 */
export async function deleteUnitKey(unitId: number): Promise<void> {
  try {
    const db = await openDatabase();

    return new Promise((resolve, reject) => {
      const transaction = db.transaction(UNIT_KEY_STORE, "readwrite");
      const store = transaction.objectStore(UNIT_KEY_STORE);

      const request = store.delete(unitId);

      request.onerror = () => {
        reject(
          new CryptoError(
            CryptoErrorType.STORAGE_ERROR,
            "Failed to delete unit key"
          )
        );
      };

      request.onsuccess = () => {
        resolve();
      };

      transaction.oncomplete = () => {
        db.close();
      };
    });
  } catch (error) {
    logger.error("Failed to delete unit key:", error);
  }
}

/**
 * Clear all stored keys
 * Call this on logout to ensure keys are removed
 */
export async function clearAllKeys(): Promise<void> {
  try {
    const db = await openDatabase();

    await Promise.all([
      new Promise<void>((resolve, reject) => {
        const transaction = db.transaction(MASTER_KEY_STORE, "readwrite");
        const request = transaction.objectStore(MASTER_KEY_STORE).clear();
        request.onerror = () => reject();
        request.onsuccess = () => resolve();
      }),
      new Promise<void>((resolve, reject) => {
        const transaction = db.transaction(UNIT_KEY_STORE, "readwrite");
        const request = transaction.objectStore(UNIT_KEY_STORE).clear();
        request.onerror = () => reject();
        request.onsuccess = () => resolve();
      }),
    ]);

    db.close();
  } catch (error) {
    logger.error("Failed to clear all keys:", error);
  }
}

/**
 * Check if IndexedDB is available
 */
export function isStorageAvailable(): boolean {
  return typeof indexedDB !== "undefined";
}
