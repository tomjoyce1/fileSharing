import { z } from "zod";

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

export const KeyBundlePrivate = z
  .object({
    preQuantum: z.object({
      identityKem: z.object({
        publicKey: z.string(), // X25519 public key
        privateKey: z.string(), // X25519 private key
      }),
      identitySigning: z.object({
        publicKey: z.string(), // Ed25519 public key
        privateKey: z.string(), // Ed25519 private key
      }),
    }),
    postQuantum: z.object({
      identityKem: z.object({
        publicKey: z.string(), // Kyber public key
        privateKey: z.string(), // Kyber private key
      }),
      identitySigning: z.object({
        publicKey: z.string(), // Dilithium public key
        privateKey: z.string(), // Dilithium private key
      }),
    }),
  })
  .strict();

export const KeyBundlePublic = z
  .object({
    preQuantum: z.object({
      identityKemPublicKey: z.string(),
      identitySigningPublicKey: z.string(),
    }),
    postQuantum: z.object({
      identityKemPublicKey: z.string(),
      identitySigningPublicKey: z.string(),
    }),
  })
  .strict();
