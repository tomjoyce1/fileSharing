export interface FileMetadataListItem {
  id: string;
  name: string;
  type: string;
  size: number;
  upload_timestamp: number;
  metadata: Uint8Array;
  metadata_nonce: Uint8Array;
  encrypted: boolean;
  owner: string;
  shared: boolean;
}

export interface EncryptedFile {
  fileId: string;
  encryptedData: Uint8Array;
  encryptedMetadata: Uint8Array;
  fileNonce: Uint8Array;
  metadataNonce: Uint8Array;
  preQuantumSignature: Uint8Array;
  postQuantumSignature?: Uint8Array;
}

export interface FileMetadata {
  original_filename: string;
  file_size_bytes: number;
  file_type: string;
  content_hash: number[];
  upload_time: string;
}

// Core types for key bundles
export interface KeyBundlePrivate {
  preQuantum: {
    identitySigning: {
      privateKey: any; // Node.js KeyObject
      publicKey: any;
    };
    identityKem: {
      privateKey: any;
      publicKey: any;
    };
  };
  postQuantum: {
    identitySigning: {
      privateKey: Uint8Array; // ML-DSA private key
      publicKey: Uint8Array;
    };
  };
}

export interface KeyBundlePublic {
  preQuantum: {
    identitySigningPublicKey: any;
    identityKemPublicKey: any;
  };
  postQuantum: {
    identitySigningPublicKey: Uint8Array;
  };
}

// File encryption data structures
export interface EncryptedData {
  encrypted_data: Uint8Array;
  nonce: Uint8Array;
}

export interface ClientFileData {
  fek: Uint8Array;           // File Encryption Key
  mek: Uint8Array;           // Metadata Encryption Key  
  fileNonce: Uint8Array;     // File nonce
  metadataNonce: Uint8Array; // Metadata nonce
}

export interface FileEncryptionResult {
  encrypted_content: EncryptedData;
  encrypted_metadata: EncryptedData;
  client_data: ClientFileData;
}

// Upload request/response types
export interface UploadRequestBody {
  file_content: string;           // base64 encrypted file
  metadata: string;               // base64 encrypted metadata
  pre_quantum_signature: string;  // base64 signature
  post_quantum_signature: string; // base64 signature
}

export interface UploadResponse {
  file_id: number;
  message: string;
}
