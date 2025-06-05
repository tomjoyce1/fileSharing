import {
  randomBytes,
  generateKeyPairSync,
  createPrivateKey,
  createPublicKey,
} from "node:crypto";
import { ml_dsa87 } from "@noble/post-quantum/ml-dsa";
import type {
  KeyBundlePrivate,
  KeyBundlePublic,
  KeyBundlePublicSerializable,
} from "../schema";
import { z } from "zod";

//generate, serialize, and deserialize key bundles for pre-quantum and post-quantum cryptography
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

  // Generate post-quantum Dilithium87 key pair for signing
  const dilithiumKeyPair = ml_dsa87.keygen(new Uint8Array(randomBytes(32)));

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
      identitySigningPublicKey: dilithiumKeyPair.publicKey,
    },
  };

  return {
    private: privateBundle,
    public: publicBundle,
  };
}

// serialize key bundles for public keys
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
      identitySigningPublicKey: Buffer.from(
        bundle.postQuantum.identitySigningPublicKey
      ).toString("base64"),
    },
  };
}

// deserialize key bundles for public keys
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
      identitySigningPublicKey: new Uint8Array(
        Buffer.from(serialized.postQuantum.identitySigningPublicKey, "base64")
      ),
    },
  };
}
