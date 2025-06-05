import { z } from "zod";
import type { KeyObject } from "node:crypto";

export const Username = z
  .string()
  .min(3, "Username must be 3-50 characters")
  .max(50)
  .regex(
    /^[a-zA-Z0-9_]+$/,
    "Username must contain only letters, numbers, and underscores"
  );

export const HexString = z
  .string()
  .regex(/^[0-9a-fA-F]+$/, "Must be a hex string");

export const Base64String = z
  .string()
  .regex(
    /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/,
    "Must be a Base64 string"
  );

// Native runtime types (use actual KeyObject and Uint8Array)
export interface KeyBundlePrivate {
  preQuantum: {
    identityKem: {
      publicKey: KeyObject;
      privateKey: KeyObject;
    };
    identitySigning: {
      publicKey: KeyObject;
      privateKey: KeyObject;
    };
  };
  postQuantum: {
    identitySigning: {
      publicKey: Uint8Array;
      privateKey: Uint8Array;
    };
  };
}

// public key bundle for API/database transport
export interface KeyBundlePublic {
  preQuantum: {
    identityKemPublicKey: KeyObject;
    identitySigningPublicKey: KeyObject;
  };
  postQuantum: {
    identitySigningPublicKey: Uint8Array;
  };
}

// file metadata for API/database transport
export interface FileMetadataListItem {
  file_id: number;
  metadata: string; // base64 encoded encrypted metadata for transport
  pre_quantum_signature: string;
  post_quantum_signature: string;
  is_owner: boolean;
  owner_username: string;
  shared_access?: {
    encrypted_fek: string;
    encrypted_fek_nonce: string;
    encrypted_mek: string;
    encrypted_mek_nonce: string;
    ephemeral_public_key: string;
    file_content_nonce: string;
    metadata_nonce: string;
  };
}

// API error response structure
export interface APIError {
  message: string;
  status: number;
}

// Serializable versions for API/database (base64 strings)
export const KeyBundlePrivateSerializable = z
  .object({
    preQuantum: z.object({
      identityKem: z.object({
        publicKey: z.string(), // X25519 public key (base64)
        privateKey: z.string(), // X25519 private key (base64)
      }),
      identitySigning: z.object({
        publicKey: z.string(), // Ed25519 public key (base64)
        privateKey: z.string(), // Ed25519 private key (base64)
      }),
    }),
    postQuantum: z.object({
      identitySigning: z.object({
        publicKey: z.string(), // Dilithium public key (base64)
        privateKey: z.string(), // Dilithium private key (base64)
      }),
    }),
  })
  .strict();

export const KeyBundlePublicSerializable = z
  .object({
    preQuantum: z.object({
      identityKemPublicKey: z.string(),
      identitySigningPublicKey: z.string(),
    }),
    postQuantum: z.object({
      identitySigningPublicKey: z.string(),
    }),
  })
  .strict();
