import sodium from "libsodium-wrappers";

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

// Connection pool for IndexedDB
let dbConnection: IDBDatabase | null = null;
let dbConnectionPromise: Promise<IDBDatabase> | null = null;
let isClosing = false;

/**
 * Opens or creates the IndexedDB database for key storage
 */
export async function openKeyDB(): Promise<IDBDatabase> {
  // If we're in the process of closing, wait for it to complete
  if (isClosing) {
    await new Promise(resolve => setTimeout(resolve, 100));
    return openKeyDB();
  }

  // If we already have a connection, return it
  if (dbConnection) {
    return dbConnection;
  }

  // If we're already in the process of opening a connection, return that promise
  if (dbConnectionPromise) {
    return dbConnectionPromise;
  }

  // Create a new connection
  dbConnectionPromise = new Promise((resolve, reject) => {
    try {
      const dbName = "DriveKeysDB";
      const dbVersion = 2;
      const request = indexedDB.open(dbName, dbVersion);

      request.onupgradeneeded = () => {
        const db = request.result;
        if (!db.objectStoreNames.contains("keys")) {
          db.createObjectStore("keys");
        }
      };

      request.onsuccess = () => {
        dbConnection = request.result;
        resolve(dbConnection);
      };

      request.onerror = (event) => {
        const error = event.target as IDBRequest | null;
        reject(new KeyError("Failed to open database", request.error as Error));
      };
    } catch (err) {
      reject(new KeyError("Failed to initialize database", err as Error));
    }
  });

  return dbConnectionPromise;
}

/**
 * Close the IndexedDB connection
 */
export async function closeKeyDB(): Promise<void> {
  if (!dbConnection) return;

  isClosing = true;
  try {
    dbConnection.close();
  } finally {
    dbConnection = null;
    dbConnectionPromise = null;
    isClosing = false;
  }
}

/**
 * Execute a database operation with retry logic
 */
async function executeDBOperation<T>(
  operation: (db: IDBDatabase) => Promise<T>,
  maxRetries = 3
): Promise<T> {
  let lastError: Error | null = null;
  
  for (let i = 0; i < maxRetries; i++) {
    try {
      const db = await openKeyDB();
      return await operation(db);
    } catch (error) {
      lastError = error as Error;
      if (error instanceof Error && error.message.includes("database connection is closing")) {
        // Wait a bit before retrying
        await new Promise(resolve => setTimeout(resolve, 100 * (i + 1)));
        continue;
      }
      throw error;
    }
  }
  
  throw lastError || new Error("Failed to execute database operation");
}

/**
 * Save key to IndexedDB
 */
export async function saveKeyToIndexedDB(
  keyName: string,
  keyData: Uint8Array,
  password: string
): Promise<void> {
  if (!(keyData instanceof Uint8Array)) {
    throw new KeyError(`Invalid key data type: ${typeof keyData}`);
  }
  
  return executeDBOperation(async (db) => {
    return new Promise<void>((resolve, reject) => {
      const tx = db.transaction("keys", "readwrite");
      const store = tx.objectStore("keys");
      const request = store.put(keyData, keyName);
      
      request.onsuccess = () => resolve();
      request.onerror = () => reject(new KeyError("Failed to save key", request.error as Error));
      tx.onerror = () => reject(new KeyError("Transaction failed", tx.error as Error));
    });
  });
}

/**
 * Get key from IndexedDB
 */
export async function getKeyFromIndexedDB(
  keyName: string,
  password: string
): Promise<Uint8Array | null> {
  return executeDBOperation(async (db) => {
    return new Promise<Uint8Array | null>((resolve, reject) => {
      const tx = db.transaction("keys", "readonly");
      const store = tx.objectStore("keys");
      const request = store.get(keyName);
      
      request.onsuccess = async () => {
        const storedKey = request.result;
        if (storedKey instanceof Uint8Array) {
          resolve(storedKey);
        } else {
          resolve(null);
        }
      };
      
      request.onerror = () => reject(new KeyError("Failed to retrieve key", request.error as Error));
      tx.onerror = () => reject(new KeyError("Transaction failed", tx.error as Error));
    });
  });
}

/**
 * Generate X25519 keypair
 */
export async function generateX25519Keypair(): Promise<{ publicKey: Uint8Array; privateKey: Uint8Array }> {
  await sodium.ready;
  const keypair = sodium.crypto_kx_keypair();
  
  if (!keypair.publicKey || !keypair.privateKey) {
    throw new Error("Failed to generate X25519 keypair");
  }

  return {
    publicKey: new Uint8Array(keypair.publicKey),
    privateKey: new Uint8Array(keypair.privateKey),
  };
}

/**
 * Generate Ed25519 keypair
 */
export async function generateEd25519Keypair(): Promise<{ publicKey: Uint8Array; privateKey: Uint8Array }> {
  await sodium.ready;
  const keypair = sodium.crypto_sign_keypair();

  if (!keypair.publicKey || !keypair.privateKey) {
    throw new Error("Failed to generate Ed25519 keypair");
  }

  return {
    publicKey: new Uint8Array(keypair.publicKey),
    privateKey: new Uint8Array(keypair.privateKey),
  };
}

/**
 * Decrypts metadata using the provided file and client data.
 * @param file - The file object containing encrypted metadata.
 * @returns The decrypted metadata as a JavaScript object.
 */
export async function decryptMetadata(file: any): Promise<any> {
  try {
    // Retrieve client data from localStorage
    const clientDataStr = localStorage.getItem(`client_data_${file.file_id || file.id}`);
    if (!clientDataStr) {
      throw new KeyError('Missing decryption keys for this file.');
    }

    const clientData = JSON.parse(clientDataStr);

    // Load MEK and metadata nonce from client data
    const mek = new Uint8Array(clientData.mek);
    const metadataNonce = new Uint8Array(clientData.metadataNonce);

    // Decode the encrypted metadata
    const encryptedMetadata =
      typeof file.metadata === 'string'
        ? Uint8Array.from(atob(file.metadata), (c) => c.charCodeAt(0))
        : file.metadata;

    // Decrypt the metadata using AES-GCM
    await sodium.ready;
    const decrypted = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
      null, // No additional data
      encryptedMetadata,
      null, // No additional data
      metadataNonce,
      mek
    );

    // Parse and return the decrypted metadata
    return JSON.parse(new TextDecoder().decode(decrypted));
  } catch (err) {
    console.error('[KeyUtils] decryptMetadata: Failed to decrypt metadata', err);
    throw new KeyError('Failed to decrypt metadata', err as Error);
  }
}

/**
 * Save an object to IndexedDB (for clientData, etc.)
 */
export async function saveObjectToIndexedDB(
  keyName: string,
  obj: any
): Promise<void> {
  return executeDBOperation(async (db) => {
    return new Promise<void>((resolve, reject) => {
      const tx = db.transaction("keys", "readwrite");
      const store = tx.objectStore("keys");
      const request = store.put(obj, keyName);
      
      request.onsuccess = () => resolve();
      request.onerror = () => reject(request.error);
      tx.onerror = () => reject(tx.error);
    });
  });
}

/**
 * Get an object from IndexedDB (for clientData, etc.)
 */
export async function getObjectFromIndexedDB(
  keyName: string
): Promise<any | null> {
  return executeDBOperation(async (db) => {
    return new Promise<any | null>((resolve, reject) => {
      const tx = db.transaction("keys", "readonly");
      const store = tx.objectStore("keys");
      const request = store.get(keyName);
      
      request.onsuccess = () => resolve(request.result || null);
      request.onerror = () => reject(request.error);
      tx.onerror = () => reject(tx.error);
    });
  });
}
