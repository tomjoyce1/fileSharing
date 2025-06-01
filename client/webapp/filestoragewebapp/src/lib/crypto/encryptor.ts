// encryptor.ts

// 


// THIS IS FOR FILE ENCRYPTION, STAGE 2




// 
import sodium from "libsodium-wrappers";

// Constants for encryption
export const FILE_KEY_SIZE = 32; // 256 bits
export const NONCE_SIZE = 12; // 96 bits for AES-GCM
export const SALT_SIZE = 16;
export const KEY_DERIVATION_ITERATIONS = 100000;

export interface EncryptionResult {
  encryptedData: Uint8Array;
  nonce: Uint8Array;
}

// File Encryption Key Components
export async function generateFEKComponents(): Promise<{ s_pre: Uint8Array; s_post: Uint8Array }> {
  return {
    s_pre: crypto.getRandomValues(new Uint8Array(FILE_KEY_SIZE)),
    s_post: crypto.getRandomValues(new Uint8Array(FILE_KEY_SIZE))
  };
}

// Derive File Encryption Key from components
export async function deriveFEK(s_pre: Uint8Array, s_post: Uint8Array): Promise<CryptoKey> {
  const encoder = new TextEncoder();
  const inputKey = new Uint8Array([...s_pre, ...s_post]);

  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    inputKey,
    { name: "HKDF" },
    false,
    ["deriveKey"]
  );

  return crypto.subtle.deriveKey(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: new Uint8Array(SALT_SIZE),
      info: encoder.encode("file_encryption_key_v1"),
    },
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    true,
    ["encrypt", "decrypt"]
  );
}

// Derive Metadata Encryption Key from FEK
export async function deriveMEK(fek: CryptoKey): Promise<CryptoKey> {
  const rawKey = await crypto.subtle.exportKey("raw", fek);
  
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    rawKey,
    { name: "HKDF" },
    false,
    ["deriveKey"]
  );

  return crypto.subtle.deriveKey(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: new Uint8Array(SALT_SIZE),
      info: new TextEncoder().encode("metadata_encryption_key_v1"),
    },
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    true,
    ["encrypt", "decrypt"]
  );
}

// Encrypt file buffer
export async function encryptFileBuffer(fek: CryptoKey, buffer: ArrayBuffer): Promise<EncryptionResult> {
  const nonce = crypto.getRandomValues(new Uint8Array(NONCE_SIZE));
  const encryptedData = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: nonce },
    fek,
    buffer
  );
  return {
    encryptedData: new Uint8Array(encryptedData),
    nonce
  };
}

// Encrypt metadata with derived MEK
export async function encryptMetadataWithFEK(fek: CryptoKey, metadata: any): Promise<EncryptionResult> {
  const mek = await deriveMEK(fek);
  const encoder = new TextEncoder();
  const plaintext = encoder.encode(JSON.stringify(metadata));
  const nonce = crypto.getRandomValues(new Uint8Array(NONCE_SIZE));

  const encryptedData = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: nonce },
    mek,
    plaintext
  );

  return {
    encryptedData: new Uint8Array(encryptedData),
    nonce
  };
}

// General encryption utility for any data
export async function encryptWithKey(
  key: CryptoKey,
  data: Uint8Array
): Promise<EncryptionResult> {
  const nonce = crypto.getRandomValues(new Uint8Array(NONCE_SIZE));
  const encryptedData = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: nonce },
    key,
    data
  );
  return {
    encryptedData: new Uint8Array(encryptedData),
    nonce
  };
}

// Decrypt file buffer
export async function decryptFileBuffer(
  fek: CryptoKey,
  encryptedData: Uint8Array,
  nonce: Uint8Array
): Promise<ArrayBuffer> {
  return crypto.subtle.decrypt(
    { name: "AES-GCM", iv: nonce },
    fek,
    encryptedData
  );
}

// Decrypt metadata with MEK
export async function decryptMetadataWithMEK(
  mek: CryptoKey,
  encryptedMetadata: Uint8Array,
  nonce: Uint8Array
): Promise<any> {
  const decrypted = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: nonce },
    mek,
    encryptedMetadata
  );
  
  const decoder = new TextDecoder();
  return JSON.parse(decoder.decode(decrypted));
}

export async function signFileRecordEd25519(
  fileId: string,
  userId: string,
  storagePath: string,
  encryptedMetadata: Uint8Array,
  privateKey: Uint8Array
) {
  await sodium.ready;

  const metadataHashBuffer = await crypto.subtle.digest("SHA-256", encryptedMetadata);
  const metadataHashArray = new Uint8Array(metadataHashBuffer);

  const dataToSign = JSON.stringify({
    file_id: fileId,
    user_id: userId,
    storage_path: storagePath,
    metadata_hash: Array.from(metadataHashArray),
  });

  const signature = sodium.crypto_sign_detached(
    sodium.from_string(dataToSign),
    privateKey
  );

  
  return {
    signature,
    dataToSign,
  };
}
