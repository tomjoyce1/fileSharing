// encryptor.ts

// 


// THIS IS FOR FILE ENCRYPTION, STAGE 2




// 
import sodium from "libsodium-wrappers";

export async function generateFEKComponents() {
  const s_pre = crypto.getRandomValues(new Uint8Array(32));
  const s_post = crypto.getRandomValues(new Uint8Array(32));
  return { s_pre, s_post };
}

export async function deriveFEK(
  s_pre: Uint8Array,
  s_post: Uint8Array,
): Promise<CryptoKey> {
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
      salt: new Uint8Array([]),
      info: encoder.encode("owner_file_fek_derivation_v1"),
    },
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    true,
    ["encrypt", "decrypt"]
  );
}

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
      salt: new Uint8Array([]),
      info: new TextEncoder().encode("file_metadata_encryption_v1"),
    },
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    true,
    ["encrypt", "decrypt"]
  );
}

export async function encryptMetadataWithFEK(fek: CryptoKey, metadata: any) {
  const mek = await deriveMEK(fek);
  return encryptMetadata(mek, metadata);
}

export async function encryptMetadata(mek: CryptoKey, metadata: any) {
  const encoder = new TextEncoder();
  const plaintext = encoder.encode(JSON.stringify(metadata));
  const nonce = crypto.getRandomValues(new Uint8Array(12));

  const encrypted = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: nonce },
    mek,
    plaintext
  );

  return {
    encryptedMetadata: new Uint8Array(encrypted),
    nonce,
  };
}

export async function encryptFileBuffer(fek: CryptoKey, buffer: ArrayBuffer) {
  const nonce = crypto.getRandomValues(new Uint8Array(12));

  const encrypted = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: nonce },
    fek,
    buffer
  );

  return {
    encryptedData: new Uint8Array(encrypted),
    nonce,
  };
}

export async function decryptFileBuffer(
  fek: CryptoKey,
  encrypted: ArrayBuffer,
  nonce: Uint8Array
): Promise<ArrayBuffer> {
  return await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: nonce },
    fek,
    encrypted
  );
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
