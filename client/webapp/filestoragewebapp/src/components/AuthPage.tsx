import React, { useState, useEffect } from "react";
import { Button } from "./ui/button";
import { Input } from "./ui/input";
import { Buffer } from "buffer";
import { ml_dsa87 } from "@noble/post-quantum/ml-dsa";
import { ml_kem1024 } from "@noble/post-quantum/ml-kem";
import sodium from "libsodium-wrappers";
import { saveObjectToIndexedDB, getObjectFromIndexedDB } from "@/lib/crypto/KeyUtils";
import { serializeKeyBundlePublic, deserializeKeyBundlePublic } from "@/lib/crypto/KeyHelper";
import scrypt from 'scrypt-js';
import { ctr } from '@noble/ciphers/aes';

// Types for key pairs
type KeyPair = {
  publicKey: Uint8Array;
  privateKey: Uint8Array;
};

// Helper: Generate random bytes
function getRandomBytes(n: number): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(n));
}

// Helper: Convert Uint8Array to base64
function uint8ArrayToBase64(arr: Uint8Array): string {
  return Buffer.from(arr).toString("base64");
}

// Save Uint8Array data to IndexedDB
async function saveKeyToIndexedDB(
  key: string,
  data: Uint8Array,
): Promise<void> {
  return new Promise((resolve, reject) => {
    // Update IndexedDB version to match the existing version (2)
    const request = indexedDB.open("DriveKeysDB", 2);

    // Ensure the object store is created properly during onupgradeneeded
    request.onupgradeneeded = (event) => {
      const db = request.result;
      console.log(`[DB] onupgradeneeded triggered. Old version: ${event.oldVersion}, New version: ${event.newVersion}`);
      if (!db.objectStoreNames.contains("keys")) {
        console.log("[DB] Creating 'keys' object store...");
        db.createObjectStore("keys");
      } else {
        console.log("[DB] 'keys' object store already exists.");
      }
    };

    // Check for the existence of the 'keys' object store in the onsuccess handler
    request.onsuccess = () => {
      const db = request.result;
      console.log(`[DB] Opened database successfully. Version: ${db.version}`);

      if (!db.objectStoreNames.contains("keys")) {
        console.error("[DB] 'keys' object store is missing. Deleting and recreating the database.");
        db.close();
        indexedDB.deleteDatabase("DriveKeysDB").onsuccess = () => {
          console.log("[DB] Database deleted successfully. Recreating...");
          const recreateRequest = indexedDB.open("DriveKeysDB", 2);
          recreateRequest.onupgradeneeded = (event) => {
            const newDb = recreateRequest.result;
            console.log(`[DB] Recreating 'keys' object store during onupgradeneeded. Old version: ${event.oldVersion}, New version: ${event.newVersion}`);
            newDb.createObjectStore("keys");
          };
          recreateRequest.onsuccess = () => {
            console.log("[DB] Database recreated successfully.");
            resolve();
          };
          recreateRequest.onerror = () => {
            console.error("[DB] Failed to recreate the database.", recreateRequest.error);
            reject(recreateRequest.error);
          };
        };
      } else {
        try {
          const tx = db.transaction("keys", "readwrite");
          const store = tx.objectStore("keys");
          store.put(data, key);
          tx.oncomplete = () => resolve();
          tx.onerror = () => reject(tx.error);
        } catch (error) {
          console.error("[DB] Transaction error:", error);
          reject(error);
        }
      }
    };

    request.onerror = () => reject(request.error);
  });
}

// Retrieve Uint8Array data from IndexedDB
async function getKeyFromIndexedDB(key: string): Promise<Uint8Array | null> {
  return new Promise((resolve, reject) => {
    // Update IndexedDB version to match the existing version (2)
    const request = indexedDB.open("DriveKeysDB", 2);

    // Ensure the object store is created properly during onupgradeneeded
    request.onupgradeneeded = (event) => {
      const db = request.result;
      if (!db.objectStoreNames.contains("keys")) {
        console.log("[DB] Creating 'keys' object store...");
        db.createObjectStore("keys");
      }
    };

    request.onsuccess = () => {
      const db = request.result;
      const tx = db.transaction("keys", "readonly");
      const store = tx.objectStore("keys");
      const getRequest = store.get(key);

      getRequest.onsuccess = () => {
        const result = getRequest.result;
        // Explicitly rehydrate to Uint8Array if it's not already
        if (result instanceof Uint8Array) {
          resolve(result);
        } else if (result && typeof result === "object" && "length" in result) {
          resolve(new Uint8Array(Object.values(result)));
        } else {
          resolve(null);
        }
      };

      getRequest.onerror = () => reject(getRequest.error);
    };

    request.onerror = () => reject(request.error);
  });
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

// Generate Dilithium keypair
async function generateMLDSAKeypair(): Promise<KeyPair> {
  const seed = getRandomBytes(32);
  console.log('[Auth] Generating ML-DSA keypair with seed length:', seed.length);
  
  const keypair = ml_dsa87.keygen(seed);

  if (!keypair.publicKey || !keypair.secretKey) {
    throw new Error("Failed to generate ML-DSA keypair");
  }

  console.log('[Auth] ML-DSA keypair generated with lengths:', {
    secretKeyLength: keypair.secretKey.length,
    publicKeyLength: keypair.publicKey.length,
    expectedSecretKeyLength: 4896,
    expectedPublicKeyLength: 2592
  });

  // Add length validation
  if (keypair.secretKey.length !== 4896) {
    console.error(`Invalid ML-DSA secret key length: got ${keypair.secretKey.length}, expected 4896`);
    throw new Error("Invalid ML-DSA key length");
  }          if (keypair.publicKey.length !== 2592) {
    console.error(`Invalid ML-DSA public key length: got ${keypair.publicKey.length}, expected 2592`);
    throw new Error("Invalid ML-DSA key length");
  }

  return {
    publicKey: keypair.publicKey,
    privateKey: keypair.secretKey,  // Note: return secretKey as privateKey
  };
}

// Generate X25519 keypair
async function generateX25519Keypair(): Promise<KeyPair> {
  await sodium.ready;

  const keypair = sodium.crypto_kx_keypair();

  if (!keypair.publicKey || !keypair.privateKey) {
    throw new Error("Failed to generate X25519 keypair");
  }

  return {
    publicKey: new Uint8Array(keypair.publicKey),
    privateKey: new Uint8Array(keypair.privateKey),
  };
}

// Generate Ed25519 keypair
async function generateEd25519Keypair(): Promise<KeyPair> {
  await sodium.ready;

  const keypair = sodium.crypto_sign_keypair();

  if (!keypair.publicKey || !keypair.privateKey) {
    throw new Error("Failed to generate Ed25519 keypair");
  }

  return {
    publicKey: new Uint8Array(keypair.publicKey),
    privateKey: new Uint8Array(keypair.privateKey),
  };
}

const KDF_PARAMS = { N: 2 ** 15, r: 8, p: 1, dkLen: 32 };
let inMemoryKEK: Uint8Array | null = null;
export function setKEK(kek: Uint8Array) { inMemoryKEK = kek; }
export function getKEK(): Uint8Array | null { return inMemoryKEK; }
export function clearKEK() { inMemoryKEK = null; }

export async function deriveKEK(password: string, salt: Uint8Array): Promise<Uint8Array> {
  const pwBytes = new TextEncoder().encode(password);
  return new Uint8Array(await scrypt.scrypt(pwBytes, salt, KDF_PARAMS.N, KDF_PARAMS.r, KDF_PARAMS.p, KDF_PARAMS.dkLen));
}

export function encryptWithKEK(plain: Uint8Array, kek: Uint8Array): { ciphertext: Uint8Array, nonce: Uint8Array } {
  const nonce = crypto.getRandomValues(new Uint8Array(16));
  const cipher = ctr(kek, nonce);
  return { ciphertext: cipher.encrypt(plain), nonce };
}

export function decryptWithKEK(ciphertext: Uint8Array, nonce: Uint8Array, kek: Uint8Array): Uint8Array {
  const cipher = ctr(kek, nonce);
  return cipher.decrypt(ciphertext);
}

export async function getDecryptedPrivateKey(username: string, keyType: 'ed25519' | 'x25519' | 'mldsa', password?: string): Promise<Uint8Array> {
  if (!inMemoryKEK) {
    const saltArr = await getObjectFromIndexedDB(`${username}_kdf_salt`);
    if (!saltArr) throw new Error('Missing KDF salt');
    const salt = new Uint8Array(saltArr);
    if (!password) {
      password = window.prompt('Enter your password to unlock your keys:') || '';
      if (!password) throw new Error('Password required');
    }
    inMemoryKEK = await deriveKEK(password, salt);
  }
  const obj = await getObjectFromIndexedDB(`${username}_${keyType}_priv`);
  if (!obj) throw new Error('Missing encrypted key');
  return decryptWithKEK(new Uint8Array(obj.ciphertext), new Uint8Array(obj.nonce), inMemoryKEK);
}

export default function AuthPage({
  onAuthSuccess,
}: {
  onAuthSuccess: (username: string) => void;
}) {
  const [mode, setMode] = useState<"login" | "register" | "forgot">("login");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [email, setEmail] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
 

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (mode === "register") {
      if (username.trim() && password.trim()) {
        setError("");
        setLoading(true);
        try {
          console.log("[Register] Generating keypairs...");

          // Generate all keypairs
          const x25519Keypair = await generateX25519Keypair();
          const ed25519Keypair = await generateEd25519Keypair();
          const mldsaKeypair = await generateMLDSAKeypair();
          
          // Verify key lengths before saving
          console.log("[Register] Verifying key lengths:", {
            x25519Private: x25519Keypair.privateKey.length,
            x25519Public: x25519Keypair.publicKey.length,
            ed25519Private: ed25519Keypair.privateKey.length,
            ed25519Public: ed25519Keypair.publicKey.length,
            mldsaPrivate: mldsaKeypair.privateKey.length,
            mldsaPublic: mldsaKeypair.publicKey.length
          });

          // Validate ML-DSA key lengths
          if (mldsaKeypair.privateKey.length !== 4896) {
            throw new Error(`Invalid ML-DSA private key length: ${mldsaKeypair.privateKey.length}`);
          }          if (mldsaKeypair.publicKey.length !== 2592) {
            throw new Error(`Invalid ML-DSA public key length: got ${mldsaKeypair.publicKey.length}, expected 2592`);
          }

          // Registration: store encrypted keys
          const salt = crypto.getRandomValues(new Uint8Array(16));
          const kek = await deriveKEK(password, salt);
          const edEnc = encryptWithKEK(ed25519Keypair.privateKey, kek);
          const xEnc = encryptWithKEK(x25519Keypair.privateKey, kek);
          const mldsaEnc = encryptWithKEK(mldsaKeypair.privateKey, kek);
          await saveObjectToIndexedDB(`${username}_ed25519_priv`, { ciphertext: Array.from(edEnc.ciphertext), nonce: Array.from(edEnc.nonce) });
          await saveObjectToIndexedDB(`${username}_x25519_priv`, { ciphertext: Array.from(xEnc.ciphertext), nonce: Array.from(xEnc.nonce) });
          await saveObjectToIndexedDB(`${username}_mldsa_priv`, { ciphertext: Array.from(mldsaEnc.ciphertext), nonce: Array.from(mldsaEnc.nonce) });
          await saveObjectToIndexedDB(`${username}_kdf_salt`, Array.from(salt));
          setKEK(kek);
          
          // Verify stored keys by decrypting and checking length
          const mldsaDecrypted = await getDecryptedPrivateKey(username, 'mldsa', password);
          if (!mldsaDecrypted || mldsaDecrypted.length !== 4896) {
            throw new Error(`ML-DSA key verification failed: decrypted length ${mldsaDecrypted?.length}`);
          }

          // Try to read back the keys immediately for debug
          console.log("Reading from key:", `${username}_ed25519_priv`);

          const edTest = await getKeyFromIndexedDB(`${username}_ed25519_priv`);
          const x25519Test = await getKeyFromIndexedDB(`${username}_x25519_priv`);
          const mldsaTest = await getKeyFromIndexedDB(`${username}_mldsa_priv`);
          console.log("mldsaTest typeof:", typeof mldsaTest);
console.log("mldsaTest instanceof Uint8Array:", mldsaTest instanceof Uint8Array);
console.log("mldsaTest length:", mldsaTest?.length);


          console.log("[Register] Read back from IndexedDB:", {
            ed: edTest,
            x25519: x25519Test,
            mldsa: mldsaTest
          });

          // Construct key bundle for server - encode all keys as base64
          console.log("[Register] Constructing key_bundle...");
          const key_bundle = {
            preQuantum: {
              identityKemPublicKey: uint8ArrayToBase64(x25519PublicKeyToSPKIDER(x25519Keypair.publicKey)),
              identitySigningPublicKey: uint8ArrayToBase64(ed25519PublicKeyToSPKIDER(ed25519Keypair.publicKey)),
            },
            postQuantum: {
              identityKemPublicKey: uint8ArrayToBase64(x25519PublicKeyToSPKIDER(x25519Keypair.publicKey)),
              identitySigningPublicKey: uint8ArrayToBase64(mldsaKeypair.publicKey), // ML-DSA-87: raw
            },
          };

          // Save public key bundle to IndexedDB
          const pubBundleString = JSON.stringify(key_bundle);
          try {
            await saveObjectToIndexedDB(`${username}_pubkey_bundle`, pubBundleString);
            console.log(`[Register] Saved public key bundle to IndexedDB for ${username}`);
          } catch (e) {
            console.error(`[Register] Failed to save public key bundle to IndexedDB for ${username}:`, e);
          }

          // Send to server (update endpoint to /api/keyhandler/register)
          console.log("[Register] Sending registration request to server...");
          console.log("[Register] Payload:", { username, key_bundle });

          const res = await fetch("/api/keyhandler/register", {
            method: "POST",
            headers: {
              "Content-Type": "application/json",
              Accept: "application/json",
            },
            body: JSON.stringify({ username, key_bundle }),
          });

          console.log("[Register] Server response status:", res.status);
          let errorMsg = "Registration failed";
          try {
            const data = await res.clone().json();
            console.log("[Register] Server response body:", data);
            if (typeof data === "object" && data && "message" in data) {
              errorMsg = (data as any).message;
            }
          } catch (e) {
            try {
              const text = await res.text();
              if (text) errorMsg = text;
            } catch {}
          }
          if (res.ok) {
            localStorage.setItem("drive_username", username);
            localStorage.setItem("drive_password", password);  
            setLoading(false);
            onAuthSuccess(username);
          } else {
            setError(errorMsg);
            setLoading(false);
          }
        } catch (err: any) {
          console.error("[Register] Exception occurred:", err);
          setError("Registration error: " + err.message);
          setLoading(false);
        }
      } else {
        setError("Please enter username and password.");
      }
      return;
    }

    if (mode === "login") {
      if (username.trim() && password.trim()) {
        setError("");
        setLoading(true);
        try {
          console.log(`[Login] Attempting to retrieve keys for user: ${username}`);
          // Get raw keys from IndexedDB
          


          const edObj = await getObjectFromIndexedDB(`${username}_ed25519_priv`);
const x25519Obj = await getObjectFromIndexedDB(`${username}_x25519_priv`);
const mldsaObj = await getObjectFromIndexedDB(`${username}_mldsa_priv`);
console.log("[Login] Retrieved encrypted keys from IndexedDB:", {
  ed: edObj,
  x25519: x25519Obj,
  mldsa: mldsaObj
});

if (!edObj || !x25519Obj || !mldsaObj) {
  setError("No keys found for this user in this browser. Please register first.");
  setLoading(false);
  return;
}
try {
  // Try to decrypt a key to check password
  await getDecryptedPrivateKey(username, 'ed25519', password);
} catch (e) {
  setError("Incorrect password or corrupted keys. Please try again.");
  setLoading(false);
  return;
}


          // After verifying the user, derive and set the KEK
          const saltArr = await getObjectFromIndexedDB(`${username}_kdf_salt`);
          if (!saltArr) throw new Error('Missing KDF salt');
          const salt = new Uint8Array(saltArr);
          const kek = await deriveKEK(password, salt);
          setKEK(kek);

          // No token logic: just set username in localStorage if keepSignedIn
          localStorage.setItem("drive_username", username);
          localStorage.setItem("drive_password", password);  

          // On login, also try to load and store the public key bundle if keys are present
          try {
            // Reconstruct the public key bundle from stored keys
            const edRaw = await getKeyFromIndexedDB(`${username}_ed25519_priv`);
            const x25519Raw = await getKeyFromIndexedDB(`${username}_x25519_priv`);
            const mldsaRaw = await getKeyFromIndexedDB(`${username}_mldsa_priv`);
            if (edRaw && x25519Raw && mldsaRaw) {
              // Rebuild the public key bundle (same as registration)
              const key_bundle = {
                preQuantum: {
                  identityKemPublicKey: uint8ArrayToBase64(x25519PublicKeyToSPKIDER(x25519Raw.slice(-32))),
                  identitySigningPublicKey: uint8ArrayToBase64(ed25519PublicKeyToSPKIDER(edRaw.slice(-32))),
                },
                postQuantum: {
                  identityKemPublicKey: uint8ArrayToBase64(x25519PublicKeyToSPKIDER(x25519Raw.slice(-32))),
                  identitySigningPublicKey: uint8ArrayToBase64(mldsaRaw.slice(-2592)),
                },
              };
              const pubBundleString = JSON.stringify(key_bundle);
              await saveObjectToIndexedDB(`${username}_pubkey_bundle`, pubBundleString);
              console.log(`[Login] Saved public key bundle to IndexedDB for ${username}`);
            }
          } catch (e) {
            console.error(`[Login] Failed to save public key bundle to IndexedDB for ${username}:`, e);
          }

          setLoading(false);
          onAuthSuccess(username);
        } catch (err: any) {
          console.error("[Login] Exception occurred:", err);
          setError("Login failed: Keys not found or corrupted");
          setLoading(false);
        }
      } else {
        setError("Please enter username and password.");
      }
    } else if (mode === "forgot") {
      if (email.trim()) {
        setError("");
        alert("Password reset link sent to " + email);
        setMode("login");
      } else {
        setError("Please enter your email.");
      }
    }
  };

  return (
    <div className="flex min-h-screen items-center justify-center bg-gray-900">
      <form
        onSubmit={handleSubmit}
        className="w-full max-w-sm rounded-lg bg-gray-800 p-8 shadow-lg"
      >
        <h2 className="mb-6 text-center text-2xl font-bold text-white">
          {mode === "login"
            ? "Login"
            : mode === "register"
              ? "Register"
              : "Forgot Password"}
        </h2>

        {mode !== "forgot" && (
          <div className="mb-4">
            <label className="mb-2 block text-gray-300">Username</label>
            <Input
              type="text"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              className="w-full rounded bg-gray-700 px-3 py-2 text-white focus:outline-none"
              autoFocus
            />
          </div>
        )}

        {mode !== "forgot" && (
          <div className="mb-4">
            <label className="mb-2 block text-gray-300">Password</label>
            <Input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className="w-full rounded bg-gray-700 px-3 py-2 text-white focus:outline-none"
            />
          </div>
        )}

        {mode === "forgot" && (
          <div className="mb-4">
            <label className="mb-2 block text-gray-300">Email</label>
            <Input
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              className="w-full rounded bg-gray-700 px-3 py-2 text-white focus:outline-none"
            />
          </div>
        )}

        {error && <div className="mb-4 text-sm text-red-500">{error}</div>}

        <Button
          type="submit"
          className="mb-2 w-full bg-blue-600 hover:bg-blue-700"
          disabled={loading}
        >
          {loading
            ? "Please wait..."
            : mode === "login"
              ? "Login"
              : mode === "register"
                ? "Register"
                : "Reset Password"}
        </Button>

        <div className="mt-4 flex justify-between">
          {mode === "login" ? (
            <>
              <button
                type="button"
                onClick={() => setMode("register")}
                className="text-blue-400 hover:text-blue-300"
              >
                Create account
              </button>
              <button
                type="button"
                onClick={() => setMode("forgot")}
                className="text-blue-400 hover:text-blue-300"
              >
                Forgot password?
              </button>
            </>
          ) : (
            <button
              type="button"
              onClick={() => setMode("login")}
              className="text-blue-400 hover:text-blue-300"
            >
              Back to login
            </button>
          )}
        </div>
      </form>
    </div>
  );
}
