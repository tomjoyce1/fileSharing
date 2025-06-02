import { ml_dsa87 } from '@noble/post-quantum/ml-dsa';
import { ctr } from '@noble/ciphers/aes';
import { randomBytes } from '@noble/ciphers/webcrypto';
import sodium from 'libsodium-wrappers';
// Types
// You may need to adjust these imports based on your actual types location
// import type { KeyBundlePrivate, FileEncryptionResult, UploadRequestBody, ClientFileData, UploadResponse } from '../types/fileTypes';

// Helper: Uint8Array to base64
function uint8ToBase64(arr: Uint8Array): string {
  return btoa(String.fromCharCode(...arr));
}
// Helper: base64 to Uint8Array
function base64ToUint8(str: string): Uint8Array {
  return Uint8Array.from(atob(str), c => c.charCodeAt(0));
}

export function encryptFile(
  fileContent: Uint8Array,
  metadata: Record<string, unknown>
) {
  // Generate random encryption keys (32 bytes for AES-256)
  const fek = randomBytes(32);
  const mek = randomBytes(32);
  // Generate random nonces (16 bytes for AES-CTR)
  const fileNonce = randomBytes(16);
  const metadataNonce = randomBytes(16);

  // Encrypt file content
  const fileCipher = ctr(fek, fileNonce);
  const encryptedContent = fileCipher.encrypt(fileContent);

  // Encrypt metadata
  const metadataString = JSON.stringify(metadata);
  const metadataCipher = ctr(mek, metadataNonce);
  const encryptedMetadata = metadataCipher.encrypt(new TextEncoder().encode(metadataString));

  return {
    encryptedContent,
    encryptedMetadata,
    clientData: {
      fek,
      mek,
      fileNonce,
      metadataNonce,
    },
  };
}

export function decryptFile(
  encryptedContent: Uint8Array,
  encryptedMetadata: Uint8Array,
  clientData: { fek: Uint8Array; mek: Uint8Array; fileNonce: Uint8Array; metadataNonce: Uint8Array }
) {
  const { fek, mek, fileNonce, metadataNonce } = clientData;
  // Decrypt file content
  const fileCipher = ctr(fek, fileNonce);
  const decryptedContent = fileCipher.decrypt(encryptedContent);
  // Decrypt metadata
  const metadataCipher = ctr(mek, metadataNonce);
  const decryptedMetadataBytes = metadataCipher.decrypt(encryptedMetadata);
  const metadataString = new TextDecoder().decode(decryptedMetadataBytes);
  const metadata = JSON.parse(metadataString);
  return { decryptedContent, metadata };
}

function createFileSignature(
  userId: number,
  encryptedFileContent: string,
  encryptedMetadata: string
): Uint8Array {
  // Create user ID buffer (4 bytes, big-endian)
  const userIdBuffer = new Uint8Array(4);
  new DataView(userIdBuffer.buffer).setUint32(0, userId, false);
  // Convert base64 strings to Uint8Arrays
  const fileBuffer = Uint8Array.from(atob(encryptedFileContent), c => c.charCodeAt(0));
  const metadataBuffer = Uint8Array.from(atob(encryptedMetadata), c => c.charCodeAt(0));
  // Concatenate: user_id + file_content + metadata
  const combined = new Uint8Array(userIdBuffer.length + fileBuffer.length + metadataBuffer.length);
  combined.set(userIdBuffer);
  combined.set(fileBuffer, userIdBuffer.length);
  combined.set(metadataBuffer, userIdBuffer.length + fileBuffer.length);
  return combined;
}

function generateFileSignatures(
  userId: number,
  encryptedFileContent: string,
  encryptedMetadata: string,
  privateKeyBundle: any
) {
  // Create the data to sign
  const dataToSign = createFileSignature(
    userId,
    encryptedFileContent,
    encryptedMetadata
  );
  // Generate pre-quantum signature using ed25519
  const preQuantumSig = sodium.crypto_sign_detached(dataToSign, privateKeyBundle.preQuantum.identitySigning.privateKey);
  // Generate post-quantum signature (ML-DSA-87)
  const postQuantumSig = ml_dsa87.sign(
    privateKeyBundle.postQuantum.identitySigning.privateKey,
    dataToSign
  );
  // Convert signatures to base64
  return {
    pre_quantum_signature: btoa(String.fromCharCode(...preQuantumSig)),
    post_quantum_signature: btoa(String.fromCharCode(...postQuantumSig)),
  };
}

export function createAuthenticatedRequest(
  method: string,
  url: string,
  body: any,
  username: string,
  privateKeyBundle: any
) {
  // Prepare request data
  const bodyString = JSON.stringify(body);
  const timestamp = new Date().toISOString();
  // Extract only the path for canonical string
  const urlPath = (() => {
    try {
      const u = new URL(url, window.location.origin);
      return u.pathname;
    } catch {
      // fallback if url is already a path
      return url;
    }
  })();
  // Canonical string: username|timestamp|HTTP_method|path|body
  const canonicalString = `${username}|${timestamp}|${method.toUpperCase()}|${urlPath}|${bodyString}`;
  const canonicalBytes = new TextEncoder().encode(canonicalString);
  // Generate request signatures
  const preQuantumSig = sodium.crypto_sign_detached(canonicalBytes, privateKeyBundle.preQuantum.identitySigning.privateKey);
  const postQuantumSig = ml_dsa87.sign(
    privateKeyBundle.postQuantum.identitySigning.privateKey,
    canonicalBytes
  );
  const preQuantumSigB64 = btoa(String.fromCharCode(...preQuantumSig));
  const postQuantumSigB64 = btoa(String.fromCharCode(...postQuantumSig));
  // Create headers
  const headers = {
    'Content-Type': 'application/json',
    'X-Username': username,
    'X-Timestamp': timestamp,
    'X-Signature-PreQuantum': preQuantumSigB64,
    'X-Signature-PostQuantum': postQuantumSigB64,
    'X-Signature': `${preQuantumSigB64}||${postQuantumSigB64}`,
  };
  // logging
  console.log("Canonical String:", canonicalString);
  console.log("Pre-Quantum Signature:", preQuantumSigB64);
  console.log("Post-Quantum Signature:", postQuantumSigB64);

  return { headers, body: bodyString };
}

export async function uploadFile(
  fileContent: Uint8Array,
  metadata: Record<string, unknown>,
  userId: number,
  username: string,
  privateKeyBundle: any,
  serverUrl: string
): Promise<{
  success: boolean;
  fileId?: number;
  clientData?: any;
  error?: string;
}> {
  try {
    // Step 1: Encrypt the file and metadata
    const encryptionResult = encryptFile(fileContent, metadata);
    // Step 2: Convert encrypted data to base64 for transmission
    const encryptedFileBase64 = uint8ToBase64(encryptionResult.encryptedContent);
    const encryptedMetadataBase64 = uint8ToBase64(encryptionResult.encryptedMetadata);
    // Step 3: Generate file signatures
    const fileSignatures = generateFileSignatures(
      userId,
      encryptedFileBase64,
      encryptedMetadataBase64,
      privateKeyBundle
    );
    // Step 4: Create request body
    const requestBody = {
      file_content: encryptedFileBase64,
      metadata: encryptedMetadataBase64,
      pre_quantum_signature: fileSignatures.pre_quantum_signature,
      post_quantum_signature: fileSignatures.post_quantum_signature,
    };
    // Step 5: Create authenticated request
    const uploadUrl = `${serverUrl}/api/fs/upload`;
    const { headers, body } = createAuthenticatedRequest(
      'POST',
      uploadUrl,
      requestBody,
      username,
      privateKeyBundle
    );

    // logging
    console.log("UPLOAD HEADERS", headers);
console.log("UPLOAD BODY", requestBody);


    // Step 6: Send HTTP request
    const response = await fetch(uploadUrl, {
      method: 'POST',
      headers,
      body,
    });
    // Step 7: Handle response
    if (!response.ok) {
      const errorData = await response.json().catch(() => ({}));
      return {
        success: false,
        error: errorData.message || `HTTP ${response.status}`,
      };
    }
    const responseData = await response.json();
    return {
      success: true,
      fileId: responseData.file_id,
      clientData: encryptionResult.clientData,
    };
  } catch (error) {
    return {
      success: false,
      error: error instanceof Error ? error.message : 'Unknown error',
    };
  }
}