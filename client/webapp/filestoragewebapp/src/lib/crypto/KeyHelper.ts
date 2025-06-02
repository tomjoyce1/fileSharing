import sodium from 'libsodium-wrappers';
import { ml_dsa87 } from '@noble/post-quantum/ml-dsa';

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
    identityKemPublicKey: Uint8Array;
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
      identityKemPublicKey: new Uint8Array(x25519.publicKey), // PQ KEM not implemented, reuse X25519 for now
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
      identityKemPublicKey: kemPublicKeySPKIDER, // Reuse preQuantum KEM key for now
      identitySigningPublicKey: btoa(String.fromCharCode(...bundle.postQuantum.identitySigningPublicKey)), // ML-DSA-87: send raw bytes
    },
  });
}

// Deserialize public key bundle from base64 JSON
export function deserializeKeyBundlePublic(json: string | object): KeyBundlePublic {
  const obj = typeof json === 'string' ? JSON.parse(json) : json;
  const kemKeyBuffer = Buffer.from(obj.preQuantum.identityKemPublicKey, 'base64');
  const signingKeyBuffer = Buffer.from(obj.preQuantum.identitySigningPublicKey, 'base64');

  console.log("Decoded KEM Key Buffer:", kemKeyBuffer);
  console.log("Decoded Signing Key Buffer:", signingKeyBuffer);
  console.log("KEM Key Buffer Length:", kemKeyBuffer.length);
  console.log("Signing Key Buffer Length:", signingKeyBuffer.length);

  return {
    preQuantum: {
      identityKemPublicKey: Uint8Array.from(atob(obj.preQuantum.identityKemPublicKey), c => c.charCodeAt(0)),
      identitySigningPublicKey: Uint8Array.from(atob(obj.preQuantum.identitySigningPublicKey), c => c.charCodeAt(0)),
    },
    postQuantum: {
      identityKemPublicKey: Uint8Array.from(atob(obj.postQuantum.identityKemPublicKey), c => c.charCodeAt(0)),
      identitySigningPublicKey: Uint8Array.from(atob(obj.postQuantum.identitySigningPublicKey), c => c.charCodeAt(0)),
    },
  };
}