import * as argon2Browser from "argon2-browser";

/**
 * Custom error class for key-related operations
 */
export class KeyError extends Error {
  constructor(
    message: string,
    public cause?: Error,
  ) {
    super(message);
    this.name = "KeyError";
  }
}

/**
 * Interface for storing encrypted private keys
 */
export interface EncryptedPrivateKey {
  cipher: Uint8Array;
  salt: Uint8Array;
  iv: Uint8Array;
}

/**
 * Constants for cryptographic operations
 */
export const CRYPTO_CONSTANTS = {
  SALT_LENGTH: 16,
  IV_LENGTH: 12,
  KEY_LENGTH: 32,
  ARGON2_MEMORY: 65536, // 64MB
  ARGON2_TIME: 3,
  ARGON2_PARALLELISM: 1,
} as const;

/**
 * Opens or creates the IndexedDB database for key storage
 */
export async function openKeyDB(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    try {
      const request = indexedDB.open("DriveKeysDB", 1);

      request.onupgradeneeded = () => {
        const db = request.result;
        if (!db.objectStoreNames.contains("keys")) {
          db.createObjectStore("keys");
        }
      };

      request.onsuccess = () => resolve(request.result);
      request.onerror = () =>
        reject(new KeyError("Failed to open database", request.error as Error));
    } catch (err) {
      reject(new KeyError("Failed to initialize database", err as Error));
    }
  });
}

/**
 * Saves a key to IndexedDB
 */
export async function saveKeyToIndexedDB(
  keyName: string,
  keyData: Uint8Array,
): Promise<void> {
  if (!(keyData instanceof Uint8Array)) {
    throw new KeyError(`Invalid key data type: ${typeof keyData}`);
  }

  try {
    const db = await openKeyDB();
    return new Promise<void>((resolve, reject) => {
      const tx = db.transaction("keys", "readwrite");
      const store = tx.objectStore("keys");

      const request = store.put(keyData, keyName);

      request.onsuccess = () => resolve();
      request.onerror = () =>
        reject(new KeyError("Failed to save key", request.error as Error));

      tx.oncomplete = () => db.close();
      tx.onerror = () =>
        reject(new KeyError("Transaction failed", tx.error as Error));
    });
  } catch (err) {
    throw new KeyError("Failed to save key to IndexedDB", err as Error);
  }
}

/**
 * Retrieves a key from IndexedDB
 */
export async function getKeyFromIndexedDB(
  keyName: string,
): Promise<Uint8Array | null> {
  try {
    const db = await openKeyDB();
    return new Promise<Uint8Array | null>((resolve, reject) => {
      const tx = db.transaction("keys", "readonly");
      const request = tx.objectStore("keys").get(keyName);

      request.onsuccess = () => {
        const result = request.result;
        if (result instanceof Uint8Array) {
          resolve(result);
        } else if (result === undefined) {
          resolve(null);
        } else {
          reject(new KeyError(`Invalid stored key type: ${typeof result}`));
        }
      };

      request.onerror = () =>
        reject(new KeyError("Failed to retrieve key", request.error as Error));
      tx.oncomplete = () => db.close();
    });
  } catch (err) {
    throw new KeyError("Failed to get key from IndexedDB", err as Error);
  }
}

/**
 * Validates a Uint8Array input
 */
function validateUint8Array(
  arr: Uint8Array,
  name: string,
  expectedLength?: number,
): void {
  if (!(arr instanceof Uint8Array)) {
    throw new KeyError(`${name} must be a Uint8Array, got: ${typeof arr}`);
  }
  if (expectedLength !== undefined && arr.length !== expectedLength) {
    throw new KeyError(
      `${name} must be ${expectedLength} bytes, got: ${arr.length}`,
    );
  }
}

/**
 * Derives an encryption key from a password using Argon2id
 */
export async function deriveKeyFromPassword(
  password: string,
  salt: Uint8Array,
): Promise<CryptoKey> {
  if (!password) {
    throw new KeyError("Password cannot be empty");
  }

  validateUint8Array(salt, "Salt", CRYPTO_CONSTANTS.SALT_LENGTH);

  try {
    const hashResult = await argon2Browser.hash({
      pass: password,
      salt,
      type: argon2Browser.ArgonType.Argon2id,
      hashLen: CRYPTO_CONSTANTS.KEY_LENGTH,
      time: CRYPTO_CONSTANTS.ARGON2_TIME,
      mem: CRYPTO_CONSTANTS.ARGON2_MEMORY,
      parallelism: CRYPTO_CONSTANTS.ARGON2_PARALLELISM,
      raw: true,
    });

    return await crypto.subtle.importKey(
      "raw",
      hashResult.hash,
      { name: "AES-GCM" },
      false,
      ["encrypt", "decrypt"],
    );
  } catch (err) {
    console.error("[deriveKeyFromPassword] Error:", err);
    throw new KeyError("Key derivation failed", err as Error);
  }
}

/**
 * Decrypts a private key using a password
 */
export async function decryptPrivateKey(
  cipher: Uint8Array,
  password: string,
  salt: Uint8Array,
  iv: Uint8Array,
): Promise<Uint8Array> {
  validateUint8Array(cipher, "Cipher");
  validateUint8Array(salt, "Salt", CRYPTO_CONSTANTS.SALT_LENGTH);
  validateUint8Array(iv, "IV", CRYPTO_CONSTANTS.IV_LENGTH);

  try {
    const key = await deriveKeyFromPassword(password, salt);
    return new Uint8Array(
      await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, cipher),
    );
  } catch (err) {
    throw new KeyError("Failed to decrypt private key", err as Error);
  }
}

/**
 * Converts a Uint8Array to a base64 string
 */
export function uint8ArrayToBase64(arr: Uint8Array): string {
  validateUint8Array(arr, "Input array");
  return Buffer.from(arr).toString("base64");
}

/**
 * Converts a base64 string to a Uint8Array
 */
export function base64ToUint8Array(base64: string): Uint8Array {
  if (typeof base64 !== "string") {
    throw new KeyError(`Expected base64 string, got: ${typeof base64}`);
  }
  return new Uint8Array(Buffer.from(base64, "base64"));
}

/**
 * Generates a random salt or IV
 */
export function generateRandomBytes(length: number): Uint8Array {
  if (!Number.isInteger(length) || length <= 0) {
    throw new KeyError(`Invalid length: ${length}`);
  }
  return crypto.getRandomValues(new Uint8Array(length));
}
