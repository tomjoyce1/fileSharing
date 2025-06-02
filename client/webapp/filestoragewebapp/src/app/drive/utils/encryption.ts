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

// Helper: SHA-256 to hex using SubtleCrypto
async function sha256Hex(base64str: string): Promise<string> {
  const bytes = Uint8Array.from(atob(base64str), c => c.charCodeAt(0));
  const hashBuffer = await window.crypto.subtle.digest('SHA-256', bytes);
  return Array.from(new Uint8Array(hashBuffer)).map(b => b.toString(16).padStart(2, '0')).join('');
}

// Canonical string for file signature (matches backend)
async function createFileSignatureCanonical(username: string, file_content: string, metadata: string): Promise<string> {
  const fileContentHash = await sha256Hex(file_content);
  const metadataHash = await sha256Hex(metadata);
  const canonical = `${username}|${fileContentHash}|${metadataHash}`;
  console.log('[FileSign] Canonical String:', canonical);
  
  console.log('[FileSign] file_content SHA256:', fileContentHash);
  console.log('[FileSign] metadata SHA256:', metadataHash);
  return canonical;
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

// Updated: Generate file signatures using canonical string
export async function generateFileSignatures(
  username: string,
  encryptedFileContent: string,
  encryptedMetadata: string,
  privateKeyBundle: any
) {
  const canonicalString = await createFileSignatureCanonical(username, encryptedFileContent, encryptedMetadata);
  const canonicalBytes = new TextEncoder().encode(canonicalString);
  // Generate pre-quantum signature using ed25519
  const preQuantumSig = sodium.crypto_sign_detached(canonicalBytes, privateKeyBundle.preQuantum.identitySigning.privateKey);
  // Generate post-quantum signature (ML-DSA-87)
  const postQuantumSig = ml_dsa87.sign(
    privateKeyBundle.postQuantum.identitySigning.privateKey,
    canonicalBytes
  );
  // Convert signatures to base64
  return {
    pre_quantum_signature: btoa(String.fromCharCode(...preQuantumSig)),
    post_quantum_signature: btoa(String.fromCharCode(...postQuantumSig)),
    canonicalString // for logging/testing
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
  console.log("Canonical String:", canonicalString.substring(0, 200));
  console.log("Pre-Quantum Signature:", preQuantumSigB64.substring(0, 200));
  console.log("Post-Quantum Signature:", postQuantumSigB64.substring(0, 200));

  return { headers, body: bodyString };
}

export async function uploadFile(
  fileContent: Uint8Array,
  metadata: Record<string, unknown>,
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
    // Step 3: Generate file signatures (await)
    const fileSignatures = await generateFileSignatures(
      username,
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
    const bodyString = JSON.stringify(requestBody);
    // Step 5: Create authenticated request (for headers, use timestamp etc. as before)
    const uploadUrl = `${serverUrl}/api/fs/upload`;
    const timestamp = new Date().toISOString();
    const canonicalString = `${username}|${timestamp}|POST|/api/fs/upload|${bodyString}`;
    const canonicalBytes = new TextEncoder().encode(canonicalString);
    const preQuantumSig = sodium.crypto_sign_detached(canonicalBytes, privateKeyBundle.preQuantum.identitySigning.privateKey);
    const postQuantumSig = ml_dsa87.sign(privateKeyBundle.postQuantum.identitySigning.privateKey, canonicalBytes);
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
    console.log('UPLOAD HEADERS', JSON.stringify(headers).substring(0, 200));
    console.log('UPLOAD BODY', bodyString.substring(0, 200));
    // Step 6: Send HTTP request
    const response = await fetch(uploadUrl, {
      method: 'POST',
      headers,
      body: bodyString,
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