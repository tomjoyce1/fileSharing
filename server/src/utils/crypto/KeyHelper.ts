import { randomBytes, generateKeyPairSync } from "node:crypto";
import { ml_kem768 } from "@noble/post-quantum/ml-kem";
import { ml_dsa65 } from "@noble/post-quantum/ml-dsa";
import type { KeyBundlePrivate, KeyBundlePublic } from "../schema";
import { z } from "zod";

export function generateKeyBundle(): {
  private: z.infer<typeof KeyBundlePrivate>;
  public: z.infer<typeof KeyBundlePublic>;
} {
  // Generate pre-quantum X25519 key pair for KEM
  const x25519KeyPair = generateKeyPairSync("x25519", {
    publicKeyEncoding: { type: "spki", format: "der" },
    privateKeyEncoding: { type: "pkcs8", format: "der" },
  });

  // Generate pre-quantum Ed25519 key pair for signing
  const ed25519KeyPair = generateKeyPairSync("ed25519", {
    publicKeyEncoding: { type: "spki", format: "der" },
    privateKeyEncoding: { type: "pkcs8", format: "der" },
  });

  // Generate post-quantum Kyber768 key pair for KEM
  const kyberKeyPair = ml_kem768.keygen();

  // Generate post-quantum Dilithium65 key pair for signing
  const dilithiumKeyPair = ml_dsa65.keygen(new Uint8Array(randomBytes(32)));

  const privateBundle: z.infer<typeof KeyBundlePrivate> = {
    preQuantum: {
      identityKem: {
        publicKey: x25519KeyPair.publicKey.toString("base64"),
        privateKey: x25519KeyPair.privateKey.toString("base64"),
      },
      identitySigning: {
        publicKey: ed25519KeyPair.publicKey.toString("base64"),
        privateKey: ed25519KeyPair.privateKey.toString("base64"),
      },
    },
    postQuantum: {
      identityKem: {
        publicKey: Buffer.from(kyberKeyPair.publicKey).toString("base64"),
        privateKey: Buffer.from(kyberKeyPair.secretKey).toString("base64"),
      },
      identitySigning: {
        publicKey: Buffer.from(dilithiumKeyPair.publicKey).toString("base64"),
        privateKey: Buffer.from(dilithiumKeyPair.secretKey).toString("base64"),
      },
    },
  };

  const publicBundle: z.infer<typeof KeyBundlePublic> = {
    preQuantum: {
      identityKemPublicKey: privateBundle.preQuantum.identityKem.publicKey,
      identitySigningPublicKey:
        privateBundle.preQuantum.identitySigning.publicKey,
    },
    postQuantum: {
      identityKemPublicKey: privateBundle.postQuantum.identityKem.publicKey,
      identitySigningPublicKey:
        privateBundle.postQuantum.identitySigning.publicKey,
    },
  };

  return {
    private: privateBundle,
    public: publicBundle,
  };
}
