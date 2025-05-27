import {
  randomBytes,
  generateKeyPairSync,
  createPrivateKey,
  createPublicKey,
} from "node:crypto";
import { ml_kem768 } from "@noble/post-quantum/ml-kem";
import { ml_dsa65 } from "@noble/post-quantum/ml-dsa";
import type {
  KeyBundlePrivate,
  KeyBundlePublic,
  KeyBundlePrivateSerializable,
  KeyBundlePublicSerializable,
} from "../schema";
import { z } from "zod";

export function generateKeyBundle(): {
  private: KeyBundlePrivate;
  public: KeyBundlePublic;
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

  // Convert buffer keys to KeyObjects for consistency
  const x25519PublicKey = createPublicKey({
    key: x25519KeyPair.publicKey,
    format: "der",
    type: "spki",
  });
  const x25519PrivateKey = createPrivateKey({
    key: x25519KeyPair.privateKey,
    format: "der",
    type: "pkcs8",
  });
  const ed25519PublicKey = createPublicKey({
    key: ed25519KeyPair.publicKey,
    format: "der",
    type: "spki",
  });
  const ed25519PrivateKey = createPrivateKey({
    key: ed25519KeyPair.privateKey,
    format: "der",
    type: "pkcs8",
  });

  const privateBundle: KeyBundlePrivate = {
    preQuantum: {
      identityKem: {
        publicKey: x25519PublicKey,
        privateKey: x25519PrivateKey,
      },
      identitySigning: {
        publicKey: ed25519PublicKey,
        privateKey: ed25519PrivateKey,
      },
    },
    postQuantum: {
      identityKem: {
        publicKey: kyberKeyPair.publicKey,
        privateKey: kyberKeyPair.secretKey,
      },
      identitySigning: {
        publicKey: dilithiumKeyPair.publicKey,
        privateKey: dilithiumKeyPair.secretKey,
      },
    },
  };

  const publicBundle: KeyBundlePublic = {
    preQuantum: {
      identityKemPublicKey: x25519PublicKey,
      identitySigningPublicKey: ed25519PublicKey,
    },
    postQuantum: {
      identityKemPublicKey: kyberKeyPair.publicKey,
      identitySigningPublicKey: dilithiumKeyPair.publicKey,
    },
  };

  return {
    private: privateBundle,
    public: publicBundle,
  };
}

export function serializeKeyBundlePublic(
  bundle: KeyBundlePublic
): z.infer<typeof KeyBundlePublicSerializable> {
  return {
    preQuantum: {
      identityKemPublicKey: bundle.preQuantum.identityKemPublicKey
        .export({ format: "der", type: "spki" })
        .toString("base64"),
      identitySigningPublicKey: bundle.preQuantum.identitySigningPublicKey
        .export({ format: "der", type: "spki" })
        .toString("base64"),
    },
    postQuantum: {
      identityKemPublicKey: Buffer.from(
        bundle.postQuantum.identityKemPublicKey
      ).toString("base64"),
      identitySigningPublicKey: Buffer.from(
        bundle.postQuantum.identitySigningPublicKey
      ).toString("base64"),
    },
  };
}

export function deserializeKeyBundlePublic(
  serialized: z.infer<typeof KeyBundlePublicSerializable>
): KeyBundlePublic {
  return {
    preQuantum: {
      identityKemPublicKey: createPublicKey({
        key: Buffer.from(serialized.preQuantum.identityKemPublicKey, "base64"),
        format: "der",
        type: "spki",
      }),
      identitySigningPublicKey: createPublicKey({
        key: Buffer.from(
          serialized.preQuantum.identitySigningPublicKey,
          "base64"
        ),
        format: "der",
        type: "spki",
      }),
    },
    postQuantum: {
      identityKemPublicKey: new Uint8Array(
        Buffer.from(serialized.postQuantum.identityKemPublicKey, "base64")
      ),
      identitySigningPublicKey: new Uint8Array(
        Buffer.from(serialized.postQuantum.identitySigningPublicKey, "base64")
      ),
    },
  };
}
