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

function logErrorDetails(context: string, error: unknown) {
  console.error(`[Error] Context: ${context}`);
  if (error instanceof Error) {
    console.error(`[Error Details] Message: ${error.message}`);
    console.error(`[Error Details] Stack: ${error.stack}`);
  } else {
    console.error(`[Error Details]`, error);
  }
}

export function deserializeKeyBundlePublic(
  serialized: z.infer<typeof KeyBundlePublicSerializable>
): KeyBundlePublic {
  try {
    console.log("[Debug] Serialized Key Bundle:", serialized);

    const kemKeyBuffer = Buffer.from(
      serialized.preQuantum.identityKemPublicKey,
      "base64"
    );
    const signingKeyBuffer = Buffer.from(
      serialized.preQuantum.identitySigningPublicKey,
      "base64"
    );

    console.log("[Debug] Decoded KEM Key Buffer:", kemKeyBuffer);
    console.log("[Debug] Decoded Signing Key Buffer:", signingKeyBuffer);

    // Log buffer lengths and types for additional debugging
    console.log("[Debug] KEM Key Buffer Length:", kemKeyBuffer.length);
    console.log("[Debug] Signing Key Buffer Length:", signingKeyBuffer.length);
    console.log("[Debug] KEM Key Buffer Type:", kemKeyBuffer.constructor.name);
    console.log(
      "[Debug] Signing Key Buffer Type:",
      signingKeyBuffer.constructor.name
    );

    // Check if the buffer is PEM, DER, or raw
    const isPem = kemKeyBuffer.toString().includes("-----BEGIN");
    console.log("[Debug] KEM Key Buffer Format:", isPem ? "PEM" : "DER or raw");

    const isPemSigning = signingKeyBuffer.toString().includes("-----BEGIN");
    console.log(
      "[Debug] Signing Key Buffer Format:",
      isPemSigning ? "PEM" : "DER or raw"
    );

    // Validate key buffers
    if (kemKeyBuffer.length === 0 || signingKeyBuffer.length === 0) {
      console.error("[Error] Key buffer is empty or invalid:", {
        kemKeyBuffer,
        signingKeyBuffer,
      });
      throw new Error("Key buffer is empty or invalid");
    }

    // Convert raw keys to DER format if necessary
    const kemKey = isPem
      ? kemKeyBuffer
      : Buffer.concat([
          Buffer.from("302a300506032b656e032100", "hex"), // ASN.1 header for X25519
          kemKeyBuffer,
        ]);

    const isAlreadyDER =
      signingKeyBuffer.length === 44 && signingKeyBuffer[0] === 0x30;
    const signingKey = isAlreadyDER
      ? signingKeyBuffer
      : Buffer.concat([
          Buffer.from("302a300506032b6570032100", "hex"),
          signingKeyBuffer,
        ]);

    return {
      preQuantum: {
        identityKemPublicKey: createPublicKey({
          key: kemKey,
          format: "der",
          type: "spki",
        }),
        identitySigningPublicKey: createPublicKey({
          key: signingKey,
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
  } catch (error) {
    logErrorDetails("Deserialize Key Bundle Public", error);
    throw error;
  }
}


