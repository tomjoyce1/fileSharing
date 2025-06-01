import { ml_dsa87 } from '@noble/post-quantum/ml-dsa';
import { openDB, type IDBPDatabase } from "idb";
import sodium from "libsodium-wrappers";
import type { FileMetadata } from "../types";

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
      const dbName = "DriveKeysDB";
      const dbVersion = 1;
      console.log(`[KeyUtils] openKeyDB: Opening IndexedDB dbName=${dbName}, dbVersion=${dbVersion}`);
      const request = indexedDB.open(dbName, dbVersion);

      request.onupgradeneeded = () => {
        const db = request.result;
        if (!db.objectStoreNames.contains("keys")) {
          db.createObjectStore("keys");
          console.log(`[KeyUtils] openKeyDB: Created object store 'keys' in dbName=${dbName}`);
        }
      };

      request.onsuccess = () => {
        console.log(`[KeyUtils] openKeyDB: Successfully opened dbName=${dbName}`);
        resolve(request.result);
      };
      request.onerror = () => {
        console.error(`[KeyUtils] openKeyDB: Failed to open dbName=${dbName}`, request.error);
        reject(new KeyError("Failed to open database", request.error as Error));
      };
    } catch (err) {
      console.error(`[KeyUtils] openKeyDB: Exception thrown`, err);
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
      console.log(`[KeyUtils] saveKeyToIndexedDB: Saving keyName=${keyName}, dataLen=${keyData.length}`);
      const tx = db.transaction("keys", "readwrite");
      const store = tx.objectStore("keys");

      const request = store.put(keyData, keyName);

      request.onsuccess = () => {
        console.log(`[KeyUtils] saveKeyToIndexedDB: Successfully saved keyName=${keyName}`);
        resolve();
      };
      request.onerror = () => {
        console.error(`[KeyUtils] saveKeyToIndexedDB: Failed to save keyName=${keyName}`, request.error);
        reject(new KeyError("Failed to save key", request.error as Error));
      };

      tx.oncomplete = () => {
        db.close();
        console.log(`[KeyUtils] saveKeyToIndexedDB: Transaction complete, db closed`);
      };
      tx.onerror = () => {
        console.error(`[KeyUtils] saveKeyToIndexedDB: Transaction failed`, tx.error);
        reject(new KeyError("Transaction failed", tx.error as Error));
      };
    });
  } catch (err) {
    console.error(`[KeyUtils] saveKeyToIndexedDB: Exception thrown`, err);
    throw new KeyError("Failed to save key to IndexedDB", err as Error);
  }
}

/**
 * Retrieves a key from IndexedDB with enhanced error handling
 */
export async function getKeyFromIndexedDB(
  keyName: string,
): Promise<Uint8Array | null> {
  try {
    const db = await openKeyDB();
    return new Promise<Uint8Array | null>((resolve, reject) => {
      console.log(`[KeyUtils] getKeyFromIndexedDB: Looking for keyName=${keyName}`);
      const tx = db.transaction("keys", "readonly");
      const store = tx.objectStore("keys");
      const request = store.get(keyName);

      request.onsuccess = () => {
        const result = request.result;
        if (result instanceof Uint8Array) {
          // Log success with key details
          console.log(`[KeyUtils] Key found: ${keyName}`, {
            type: 'Uint8Array',
            length: result.length,
            firstBytes: Array.from(result.slice(0, 4))
          });
          resolve(result);
        } else if (result && typeof result === 'object' && 'length' in result) {
          // Handle array-like objects by converting to Uint8Array
          console.log(`[KeyUtils] Converting array-like to Uint8Array: ${keyName}`);
          const uint8Array = new Uint8Array(Object.values(result));
          resolve(uint8Array);
        } else if (result === undefined || result === null) {
          console.warn(`[KeyUtils] Key not found: ${keyName}`);
          resolve(null);
        } else {
          console.error(`[KeyUtils] Invalid key format: ${keyName}`, {
            type: typeof result,
            value: result
          });
          reject(new KeyError(`Invalid stored key type: ${typeof result}`));
        }
      };

      request.onerror = () => {
        console.error(`[KeyUtils] Failed to retrieve key: ${keyName}`, request.error);
        reject(new KeyError("Failed to retrieve key", request.error as Error));
      };

      tx.oncomplete = () => {
        db.close();
        console.log(`[KeyUtils] Transaction complete for: ${keyName}`);
      };
    });
  } catch (err) {
    console.error(`[KeyUtils] Error accessing IndexedDB:`, err);
    throw new KeyError("Failed to access IndexedDB", err as Error);
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
 * Key storage functions
 */
const DB_NAME = "FileEncryptionStore";
const KEY_STORE = "keys";
const KEY_STORE_ED25519 = "ed25519_keys";
const KEY_STORE_MLDSA = "mldsa_keys";

export interface KeyStorage {
  s_pre: number[];
  s_post: number[];
  file_nonce: number[];
  metadata_nonce: number[];
}

// Store encryption keys in IndexedDB
export async function storeEncryptionKeys(fileId: string, keys: KeyStorage): Promise<void> {
  const db = await openDB(DB_NAME, 1, {
    upgrade(db: IDBPDatabase) {
      if (!db.objectStoreNames.contains(KEY_STORE)) {
        db.createObjectStore(KEY_STORE);
      }
    },
  });

  await db.put(KEY_STORE, keys, fileId);
}

// Get encryption keys from IndexedDB
export async function getEncryptionKeys(fileId: string): Promise<KeyStorage | undefined> {
  const db = await openDB(DB_NAME, 1);
  return db.get(KEY_STORE, fileId);
}

// Sign file data with Ed25519 (pre-quantum)
export async function signPreQuantum(
  fileId: string,
  username: string,
  encryptedFile: Uint8Array,
  encryptedMetadata: Uint8Array,
  privateKey: Uint8Array
): Promise<Uint8Array> {
  // Concatenate all data to sign
  const dataToSign = new Uint8Array([
    ...new TextEncoder().encode(fileId),
    ...new TextEncoder().encode(username),
    ...encryptedFile,
    ...encryptedMetadata,
  ]);

  // Sign with Ed25519
  await sodium.ready;
  return sodium.crypto_sign_detached(dataToSign, privateKey);
}

/**
 * Interface for ML-DSA-87 key bundle
 */
export interface MLDSAKeyBundle {
  privateKey: Uint8Array;
  publicKey: Uint8Array;
}

// Constants for ML-DSA-87
export const ML_DSA_CONSTANTS = {
  SEED_LENGTH: 32,
  PUBLIC_KEY_LENGTH: 2592,  // Updated based on actual library output
  PRIVATE_KEY_LENGTH: 4896,
  SIGNATURE_LENGTH: 2701
} as const;

/**
 * Generate a new ML-DSA-87 key pair
 */
export function generateMLDSAKeyPair(): MLDSAKeyBundle {
  try {
    // Use a random 32-byte seed for keygen
    const seed = crypto.getRandomValues(new Uint8Array(32));
    const keypair = ml_dsa87.keygen(seed);
    if (!keypair.secretKey || !keypair.publicKey) {
      throw new Error('ML-DSA-87 key generation failed: Missing secret or public key');
    }
    console.log('[KeyUtils] ML-DSA-87 keypair generated:', {
      secretKeyLength: keypair.secretKey.length,
      publicKeyLength: keypair.publicKey.length,
      expectedSecretKeyLength: ML_DSA_CONSTANTS.PRIVATE_KEY_LENGTH,
      expectedPublicKeyLength: ML_DSA_CONSTANTS.PUBLIC_KEY_LENGTH
    });
    if (keypair.secretKey.length !== ML_DSA_CONSTANTS.PRIVATE_KEY_LENGTH) {
      console.warn(`[KeyUtils] Warning: ML-DSA-87 secret key length mismatch: expected ${ML_DSA_CONSTANTS.PRIVATE_KEY_LENGTH}, got ${keypair.secretKey.length}`);
    }
    return { privateKey: keypair.secretKey, publicKey: keypair.publicKey };
  } catch (err) {
    console.error('ML-DSA-87 key generation failed:', err);
    throw new KeyError('Post-quantum key generation failed', err as Error);
  }
}

/**
 * Sign data using ML-DSA-87
 */
export function signMLDSA(
  privateKey: Uint8Array,
  data: Uint8Array
): Uint8Array {
  try {
    return ml_dsa87.sign(privateKey, data);
  } catch (err) {
    console.error('ML-DSA-87 signing failed:', err);
    throw new KeyError('Post-quantum signing failed', err as Error);
  }
}

/**
 * Verify ML-DSA-87 signature
 */
export function verifyMLDSA(
  publicKey: Uint8Array,
  signature: Uint8Array,
  data: Uint8Array
): boolean {
  try {
    return ml_dsa87.verify(data, signature, publicKey);
  } catch (err) {
    console.error('ML-DSA-87 verification failed:', err);
    return false;
  }
}

// Post-quantum cryptography constants
export const PQ_CONSTANTS = {
  ML_DSA_SEED_LENGTH: 32,
  ML_DSA_PK_LENGTH: 2592,  // Updated based on actual library output
  ML_DSA_SK_LENGTH: 4896,
  ML_DSA_SIG_LENGTH: 2701
} as const;

// Generate a post-quantum key pair using ML-DSA-87
export async function generatePostQuantumKeyPair(): Promise<{ 
  publicKey: Uint8Array; 
  privateKey: Uint8Array; 
}> {
  try {
    // Generate random seed for key generation
    const seed = crypto.getRandomValues(new Uint8Array(PQ_CONSTANTS.ML_DSA_SEED_LENGTH));
    // Use the seed to generate the key pair
    const keypair = ml_dsa87.keygen(seed); // FIX: use keygen, not create
    return {
      privateKey: keypair.secretKey, // FIX: use secretKey, not privateKey
      publicKey: keypair.publicKey
    };
  } catch (err) {
    console.error('Failed to generate ML-DSA-87 key pair:', err);
    throw new KeyError('Post-quantum key generation failed', err as Error);
  }
}

// Sign with ML-DSA-87 post-quantum algorithm
export async function signPostQuantum(
  fileId: string,
  username: string,
  encryptedFile: Uint8Array,
  encryptedMetadata: Uint8Array,
  privateKey: Uint8Array
): Promise<Uint8Array> {
  try {
    console.log('[KeyUtils] ML-DSA-87 signing input validation:', {
      privateKeyLength: privateKey.length,
      expectedKeyLength: ML_DSA_CONSTANTS.PRIVATE_KEY_LENGTH,
      fileIdLength: new TextEncoder().encode(fileId).length,
      usernameLength: new TextEncoder().encode(username).length,
      encryptedFileLength: encryptedFile.length,
      encryptedMetadataLength: encryptedMetadata.length
    });

    if (!privateKey || !(privateKey instanceof Uint8Array)) {
      throw new KeyError('Invalid ML-DSA-87 private key format');
    }

    if (privateKey.length !== ML_DSA_CONSTANTS.PRIVATE_KEY_LENGTH) {
      throw new KeyError(`Invalid ML-DSA-87 private key length: expected ${ML_DSA_CONSTANTS.PRIVATE_KEY_LENGTH}, got ${privateKey.length}`);
    }

    // Concatenate all data to sign
    const dataToSign = new Uint8Array([
      ...new TextEncoder().encode(fileId),
      ...new TextEncoder().encode(username),
      ...encryptedFile,
      ...encryptedMetadata
    ]);

    console.log('[KeyUtils] ML-DSA-87 signing data:', {
      totalLength: dataToSign.length,
      components: {
        fileId: new TextEncoder().encode(fileId).length,
        username: new TextEncoder().encode(username).length,
        encryptedFile: encryptedFile.length,
        encryptedMetadata: encryptedMetadata.length
      }
    });

    // Sign with ML-DSA-87
    try {
      const signature = ml_dsa87.sign(privateKey, dataToSign);
      console.log('[KeyUtils] ML-DSA-87 signature generated:', {
        signatureLength: signature.length,
        expectedLength: ML_DSA_CONSTANTS.SIGNATURE_LENGTH
      });
      return signature;
    } catch (signError) {
      console.error('[KeyUtils] ML-DSA-87 signing operation failed:', signError);
      throw new KeyError('ML-DSA-87 signing operation failed', signError as Error);
    }
  } catch (err) {
    console.error('[KeyUtils] ML-DSA-87 signing failed:', err);
    throw new KeyError('Post-quantum signing failed', err as Error);
  }
}

// Sign file record with both pre and post-quantum signatures
export async function signFileRecord(
  fileId: string,
  username: string,
  encryptedFile: Uint8Array,
  encryptedMetadata: Uint8Array
): Promise<{ preQuantumSignature: Uint8Array; postQuantumSignature?: Uint8Array }> {
  // Get the Ed25519 private key for pre-quantum signature
  const edKeyRaw = await getKeyFromIndexedDB(`${username}_ed25519_priv`);
  if (!edKeyRaw) {
    throw new KeyError("No Ed25519 key found. Please log in again.");
  }

  // Validate Ed25519 key
  if (!(edKeyRaw instanceof Uint8Array) || edKeyRaw.length !== 64) {
    throw new KeyError(`Invalid Ed25519 key format or length: expected 64 bytes, got ${edKeyRaw?.length}`);
  }

  // Create pre-quantum signature with Ed25519
  const preQuantumSignature = await signPreQuantum(
    fileId,
    username,
    encryptedFile,
    encryptedMetadata,
    edKeyRaw
  );

  // Try to get ML-DSA key for post-quantum signature
  try {
    const mldsaKey = await getKeyFromIndexedDB(`${username}_mldsa_priv`);
    if (!mldsaKey) {
      throw new KeyError("No ML-DSA-87 key found");
    }

    // Validate ML-DSA key
    if (!(mldsaKey instanceof Uint8Array) || mldsaKey.length !== ML_DSA_CONSTANTS.PRIVATE_KEY_LENGTH) {
      throw new KeyError(`Invalid ML-DSA-87 key format or length: expected ${ML_DSA_CONSTANTS.PRIVATE_KEY_LENGTH} bytes, got ${mldsaKey?.length}`);
    }

    const postQuantumSignature = await signPostQuantum(
      fileId,
      username,
      encryptedFile,
      encryptedMetadata,
      mldsaKey
    );

    return { preQuantumSignature, postQuantumSignature };
  } catch (err) {
    console.warn("[KeyUtils] Post-quantum signature failed:", err);
    // Return only pre-quantum signature if post-quantum fails
    return { preQuantumSignature };
  }
}

// Correct Ed25519 key generation and storage for browser/libsodium:
export async function generateAndStoreEd25519Key(username: string) {
  await sodium.ready;
  const keypair = sodium.crypto_sign_keypair();
  console.log('Generated Ed25519 privateKey length:', keypair.privateKey.length, keypair.privateKey);
  await saveKeyToIndexedDB(`${username}_ed25519_priv`, keypair.privateKey);
  await saveKeyToIndexedDB(`${username}_ed25519_pub`, keypair.publicKey);
  return keypair;
}


/**
 * Helper to fetch a raw private key from IndexedDB.
 * Returns the raw private key as Uint8Array, or throws if not found or invalid.
 *
 * @param keyName - The IndexedDB key name (e.g., `${username}_ed25519_priv`)
 * @returns Promise<Uint8Array> - The raw private key
 */
export async function getPrivateKeyFromIndexedDB(
  keyName: string
): Promise<Uint8Array> {
  const key = await getKeyFromIndexedDB(keyName);
  if (!key) {
    console.error(`[KeyUtils] No key found in IndexedDB for ${keyName}`);
    throw new KeyError(`No key found in IndexedDB for ${keyName}`);
  }
  if (!(key instanceof Uint8Array)) {
    console.error(`[KeyUtils] Invalid key format for ${keyName}:`, typeof key);
    throw new KeyError(`Invalid key format for ${keyName}`);
  }
  
  // Log key length before validation
  console.log(`[KeyUtils] Retrieved key from IndexedDB: keyName=${keyName}, length=${key.length}`);
  
  // Validate key length for known key types
  if (keyName.endsWith('_ed25519_priv') && key.length !== 64) {
    console.error(`[KeyUtils] Ed25519 key length mismatch for ${keyName}: expected 64, got ${key.length}`);
    throw new KeyError(`Ed25519 key for ${keyName} has invalid length: expected 64, got ${key.length}`);
  }
  if (keyName.endsWith('_x25519_priv') && key.length !== 32) {
    console.error(`[KeyUtils] X25519 key length mismatch for ${keyName}: expected 32, got ${key.length}`);
    throw new KeyError(`X25519 key for ${keyName} has invalid length: expected 32, got ${key.length}`);
  }
  if (keyName.endsWith('_mldsa_priv')) {
    console.log(`[KeyUtils] ML-DSA-87 key validation for ${keyName}:`, {
      actualLength: key.length,
      expectedLength: ML_DSA_CONSTANTS.PRIVATE_KEY_LENGTH
    });
    if (key.length !== ML_DSA_CONSTANTS.PRIVATE_KEY_LENGTH) {
      console.error(`[KeyUtils] ML-DSA-87 key length mismatch for ${keyName}:`, {
        expected: ML_DSA_CONSTANTS.PRIVATE_KEY_LENGTH,
        got: key.length
      });
      throw new KeyError(`ML-DSA-87 key for ${keyName} has invalid length: expected ${ML_DSA_CONSTANTS.PRIVATE_KEY_LENGTH}, got ${key.length}`);
    }
  }
  return key;
}

// Generate post-quantum keys from a given seed
export async function generatePostQuantumKeys(seed: Uint8Array): Promise<{ privateKey: Uint8Array; publicKey: Uint8Array }> {
  try {
    if (seed.length !== ML_DSA_CONSTANTS.SEED_LENGTH) {
      throw new KeyError(`Invalid seed length for ML-DSA-87: expected ${ML_DSA_CONSTANTS.SEED_LENGTH}, got ${seed.length}`);
    }

    console.log('[KeyUtils] Generating ML-DSA-87 keypair from seed:', {
      seedLength: seed.length,
      expectedSeedLength: ML_DSA_CONSTANTS.SEED_LENGTH
    });

    const keypair = ml_dsa87.keygen(seed);
    console.log('[KeyUtils] Generated ML-DSA-87 keypair:', {
      privateKeyLength: keypair.secretKey.length,
      publicKeyLength: keypair.publicKey.length,
      expectedPrivateKeyLength: ML_DSA_CONSTANTS.PRIVATE_KEY_LENGTH,
      expectedPublicKeyLength: ML_DSA_CONSTANTS.PUBLIC_KEY_LENGTH
    });

    return {
      privateKey: keypair.secretKey,
      publicKey: keypair.publicKey
    };
  } catch (err) {
    console.error('[KeyUtils] Failed to generate ML-DSA-87 keypair:', err);
    throw new KeyError('Failed to generate post-quantum keypair', err as Error);
  }
}

// Store private key in IndexedDB
export async function storePrivateKeyInIndexedDB(keyName: string, key: Uint8Array): Promise<void> {
  try {
    console.log('[KeyUtils] Storing ML-DSA-87 private key in IndexedDB:', {
      keyName,
      keyLength: key.length,
      expectedLength: ML_DSA_CONSTANTS.PRIVATE_KEY_LENGTH
    });

    if (key.length !== ML_DSA_CONSTANTS.PRIVATE_KEY_LENGTH) {
      throw new KeyError(`Invalid ML-DSA-87 private key length: expected ${ML_DSA_CONSTANTS.PRIVATE_KEY_LENGTH}, got ${key.length}`);
    }

    await saveKeyToIndexedDB(keyName, key);
    console.log(`[KeyUtils] Successfully stored key: ${keyName}`);
  } catch (err) {
    console.error('[KeyUtils] Failed to store private key in IndexedDB:', err);
    throw new KeyError('Failed to store private key', err as Error);
  }
}

/**
 * Validate all required keys for a user
 */
export async function validateUserKeys(username: string): Promise<boolean> {
  try {
    // Check for all required keys
    const edKey = await getKeyFromIndexedDB(`${username}_ed25519_priv`);
    const x25519Key = await getKeyFromIndexedDB(`${username}_x25519_priv`);
    const mldsaKey = await getKeyFromIndexedDB(`${username}_mldsa_priv`);

    // Validate Ed25519 key
    if (!edKey || !(edKey instanceof Uint8Array) || edKey.length !== 64) {
      console.error('[KeyUtils] Invalid Ed25519 key');
      return false;
    }

    // Validate X25519 key
    if (!x25519Key || !(x25519Key instanceof Uint8Array) || x25519Key.length !== 32) {
      console.error('[KeyUtils] Invalid X25519 key');
      return false;
    }

    // Validate ML-DSA key
    if (!mldsaKey || !(mldsaKey instanceof Uint8Array)) {
      console.error('[KeyUtils] Invalid ML-DSA key');
      return false;
    }

    return true;
  } catch (err) {
    console.error('[KeyUtils] Error validating keys:', err);
    return false;
  }
}

/**
 * Clear all keys for a user
 */
export async function clearUserKeys(username: string): Promise<void> {
  const db = await openKeyDB();
  const tx = db.transaction("keys", "readwrite");
  const store = tx.objectStore("keys");

  await Promise.all([
    store.delete(`${username}_ed25519_priv`),
    store.delete(`${username}_x25519_priv`),
    store.delete(`${username}_mldsa_priv`)
  ]);

  await new Promise<void>((resolve, reject) => {
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}
