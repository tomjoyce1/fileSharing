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

/**
 * Opens or creates the IndexedDB database for key storage
 */
export async function openKeyDB(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    try {
      const dbName = "DriveKeysDB";
      const dbVersion = 2;
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

      request.onerror = (event) => {
        const error = event.target as IDBRequest | null;
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
  // NOTE: For real password-based encryption, use a proper KDF and encrypt the key before storage.
  try {
    await sodium.ready;
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
 * Get key from IndexedDB
 */
export async function getKeyFromIndexedDB(
  keyName: string,
  password: string
): Promise<Uint8Array | null> {
  try {
    const db = await openKeyDB();
    return new Promise<Uint8Array | null>((resolve, reject) => {
      console.log(`[KeyUtils] getKeyFromIndexedDB: Looking for keyName=${keyName}`);
      const tx = db.transaction("keys", "readonly");
      const store = tx.objectStore("keys");
      const request = store.get(keyName);
      request.onsuccess = async () => {
        const storedKey = request.result;
        if (storedKey instanceof Uint8Array) {
          // NOTE: For real password-based encryption, decrypt the key here using the password.
          resolve(storedKey);
        } else {
          resolve(null);
        }
      };
      request.onerror = () => {
        reject(new KeyError("Failed to retrieve key", request.error as Error));
      };
      tx.oncomplete = () => {
        db.close();
      };
    });
  } catch (err) {
    console.error(`[KeyUtils] getKeyFromIndexedDB: Exception thrown`, err);
    throw new KeyError("Failed to retrieve key from IndexedDB", err as Error);
  }
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
