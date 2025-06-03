import sodium from 'libsodium-wrappers';
import { ml_dsa87 } from '@noble/post-quantum/ml-dsa';
// import { createPublicKey } from 'crypto';
import { z } from 'zod';

export type KeyBundlePrivate = {
  preQuantum: {
    identityKem: { privateKey: Uint8Array };
    identitySigning: { privateKey: Uint8Array };
  };
  postQuantum: {
    identitySigning: { privateKey: Uint8Array };
  };
};

export type KeyBundlePublic = {
  preQuantum: {
    identityKemPublicKey: Uint8Array;
    identitySigningPublicKey: Uint8Array;
  };
  postQuantum: {
    identitySigningPublicKey: Uint8Array;
  };
};

export async function generateKeyBundle(): Promise<{ private: KeyBundlePrivate; public: KeyBundlePublic }> {
  await sodium.ready;
  // X25519 (KEM)
  const x25519 = sodium.crypto_kx_keypair();
  // Ed25519 (signing)
  const ed25519 = sodium.crypto_sign_keypair();
  // ML-DSA-87 (Dilithium)
  const mldsaSeed = sodium.randombytes_buf(32);
  const mldsa = ml_dsa87.keygen(mldsaSeed);

  const privateBundle: KeyBundlePrivate = {
    preQuantum: {
      identityKem: { privateKey: new Uint8Array(x25519.privateKey) },
      identitySigning: { privateKey: new Uint8Array(ed25519.privateKey) },
    },
    postQuantum: {
      identitySigning: { privateKey: new Uint8Array(mldsa.secretKey) },
    },
  };
  const publicBundle: KeyBundlePublic = {
    preQuantum: {
      identityKemPublicKey: new Uint8Array(x25519.publicKey),
      identitySigningPublicKey: new Uint8Array(ed25519.publicKey),
    },
    postQuantum: {
      identitySigningPublicKey: new Uint8Array(mldsa.publicKey),
    },
  };
  return { private: privateBundle, public: publicBundle };
}

// ASN.1 DER for Ed25519 public key (RFC 8410)
function ed25519PublicKeyToSPKIDER(pubkey: Uint8Array): Uint8Array {
  const prefix = Uint8Array.from([
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00
  ]);
  const out = new Uint8Array(prefix.length + pubkey.length);
  out.set(prefix, 0);
  out.set(pubkey, prefix.length);
  return out;
}

// ASN.1 DER for X25519 public key (RFC 8410)
function x25519PublicKeyToSPKIDER(pubkey: Uint8Array): Uint8Array {
  const prefix = Uint8Array.from([
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x03, 0x21, 0x00
  ]);
  const out = new Uint8Array(prefix.length + pubkey.length);
  out.set(prefix, 0);
  out.set(pubkey, prefix.length);
  return out;
}

export function serializeKeyBundlePublic(bundle: KeyBundlePublic): string {
  const kemPublicKeySPKIDER = btoa(
    String.fromCharCode(...x25519PublicKeyToSPKIDER(bundle.preQuantum.identityKemPublicKey))
  );
  const signingPublicKeySPKIDER = btoa(
    String.fromCharCode(...ed25519PublicKeyToSPKIDER(bundle.preQuantum.identitySigningPublicKey))
  );

  return JSON.stringify({
    preQuantum: {
      identityKemPublicKey: kemPublicKeySPKIDER,
      identitySigningPublicKey: signingPublicKeySPKIDER,
    },
    postQuantum: {
      identitySigningPublicKey: btoa(String.fromCharCode(...bundle.postQuantum.identitySigningPublicKey)), // ML-DSA-87: send raw bytes
    },
  });
}

// Deserialize public key bundle from base64 JSON
export function deserializeKeyBundlePublic(
  serialized: any // Accept plain object
): KeyBundlePublic {
  console.log("[Debug] Serialized Key Bundle:", serialized);

  const kemKeyBuffer = Buffer.from(
    serialized.preQuantum.identityKemPublicKey,
    "base64"
  );
  const signingKeyBuffer = Buffer.from(
    serialized.preQuantum.identitySigningPublicKey,
    "base64"
  );

  console.log("Decoded KEM Key Buffer:", kemKeyBuffer);
  console.log("Decoded Signing Key Buffer:", signingKeyBuffer);
  console.log("KEM Key Buffer Length:", kemKeyBuffer.length);
  console.log("Signing Key Buffer Length:", signingKeyBuffer.length);

  return {
    preQuantum: {
      identityKemPublicKey: new Uint8Array(kemKeyBuffer),
      identitySigningPublicKey: new Uint8Array(signingKeyBuffer),
    },
    postQuantum: {
      identitySigningPublicKey: new Uint8Array(
        Buffer.from(serialized.postQuantum.identitySigningPublicKey, "base64")
      ),
    },
  };
}

// Extracts the raw 32-byte Ed25519 public key from a DER-encoded SPKI buffer
export function extractEd25519RawPublicKeyFromDER(der: Uint8Array | Buffer): Uint8Array {
  // Ed25519 SPKI DER header is always 12 bytes
  // 0x30 0x2a 0x30 0x05 0x06 0x03 0x2b 0x65 0x70 0x03 0x21 0x00
  // [12 bytes header][32 bytes raw key]
  if (der.length === 44 && der[0] === 0x30 && der[1] === 0x2a) {
    return der.slice(12, 44);
  }
  throw new Error("Invalid DER-encoded Ed25519 public key");
}