import React, { useState, useEffect } from "react";
import { Button } from "~/components/ui/button";
import { Input } from "~/components/ui/input";
import { Buffer } from "buffer";
import { ml_dsa87 } from "@noble/post-quantum/ml-dsa";
import { ml_kem1024 } from "@noble/post-quantum/ml-kem";
import sodium from "libsodium-wrappers";
import { scrypt } from "@noble/hashes/scrypt";

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

// Scrypt KDF using WebCrypto (Node.js polyfill for browser)
// Scrypt KDF using scrypt-kdf (npm package)
async function deriveKeyFromPassword(
  password: string,
  salt: Uint8Array,
): Promise<Uint8Array> {
  const passwordBytes = new TextEncoder().encode(password);

  // scrypt parameters: N=2^15 (32768), r=8, p=1, key length=32 bytes
  const N = 1 << 15;
  const r = 8;
  const p = 1;
  const dkLen = 32;

  const derivedKey = await scrypt(passwordBytes, salt, { N, r, p, dkLen });
  return new Uint8Array(derivedKey);
}
async function getAesGcmKeyFromRaw(rawKey: Uint8Array): Promise<CryptoKey> {
  return await crypto.subtle.importKey(
    "raw",
    rawKey,
    { name: "AES-GCM" },
    false,
    ["encrypt", "decrypt"],
  );
}

// Save Uint8Array data to IndexedDB
async function saveKeyToIndexedDB(
  key: string,
  data: Uint8Array,
): Promise<void> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open("KeyStore", 1);

    request.onupgradeneeded = () => {
      const db = request.result;
      if (!db.objectStoreNames.contains("keys")) {
        db.createObjectStore("keys");
      }
    };

    request.onsuccess = () => {
      const db = request.result;
      const tx = db.transaction("keys", "readwrite");
      const store = tx.objectStore("keys");
      store.put(data, key);
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(tx.error);
    };

    request.onerror = () => reject(request.error);
  });
}

// Retrieve Uint8Array data from IndexedDB
async function getKeyFromIndexedDB(key: string): Promise<Uint8Array | null> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open("KeyStore", 1);

    request.onupgradeneeded = () => {
      const db = request.result;
      if (!db.objectStoreNames.contains("keys")) {
        db.createObjectStore("keys");
      }
    };

    request.onsuccess = () => {
      const db = request.result;
      const tx = db.transaction("keys", "readonly");
      const store = tx.objectStore("keys");
      const getRequest = store.get(key);
      getRequest.onsuccess = () => {
        resolve(getRequest.result || null);
      };
      getRequest.onerror = () => reject(getRequest.error);
    };

    request.onerror = () => reject(request.error);
  });
}
// AES-GCM encryption for private keys using scrypt-kdf
async function encryptPrivateKey(
  privateKey: Uint8Array,
  password: string,
): Promise<{ cipher: Uint8Array; salt: Uint8Array; iv: Uint8Array }> {
  const salt = getRandomBytes(16);
  const iv = getRandomBytes(12);

  const rawKey = await deriveKeyFromPassword(password, salt);
  const key = await getAesGcmKeyFromRaw(rawKey);

  const cipher = new Uint8Array(
    await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, privateKey),
  );

  return { cipher, salt, iv };
}

async function decryptPrivateKey(
  cipher: Uint8Array,
  password: string,
  salt: Uint8Array,
  iv: Uint8Array,
): Promise<Uint8Array> {
  const rawKey = await deriveKeyFromPassword(password, salt);
  const key = await getAesGcmKeyFromRaw(rawKey);

  const decrypted = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv },
    key,
    cipher,
  );
  return new Uint8Array(decrypted);
}

// Generate Dilithium keypair
async function generateMLDSAKeypair(): Promise<KeyPair> {
  const seed = getRandomBytes(32);
  const keypair = ml_dsa87.keygen(seed);

  if (!keypair.publicKey || !keypair.secretKey) {
    throw new Error("Failed to generate ML-DSA keypair");
  }

  return {
    publicKey: keypair.publicKey,
    privateKey: keypair.secretKey,
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

// Test function to verify key derivation
// async function testKeyDerivation() {
//   console.log("[TEST] Starting key derivation tests...");

//   try {
//     // Test 1: Basic test with simple password and salt
//     const test1Password = "testpassword";
//     const test1Salt = getRandomBytes(16);
//     console.log("[TEST 1] Simple password test");
//     console.log("Password:", test1Password);
//     console.log("Salt:", uint8ArrayToBase64(test1Salt));
//     await deriveKeyFromPassword(test1Password, test1Salt);
//     console.log("[TEST 1] Success - Key derived successfully");

//     // Test 2: Test with special characters
//     const test2Password = "test!@#$%^&*()";
//     const test2Salt = getRandomBytes(16);
//     console.log("[TEST 2] Special characters password test");
//     console.log("Password:", test2Password);
//     console.log("Salt:", uint8ArrayToBase64(test2Salt));
//     await deriveKeyFromPassword(test2Password, test2Salt);
//     console.log("[TEST 2] Success - Key derived successfully");

//     // Test 3: Test with very short password (like in the error case)
//     const test3Password = "a";
//     const test3Salt = getRandomBytes(16);
//     console.log("[TEST 3] Short password test");
//     console.log("Password:", test3Password);
//     console.log("Salt:", uint8ArrayToBase64(test3Salt));
//     await deriveKeyFromPassword(test3Password, test3Salt);
//     console.log("[TEST 3] Success - Key derived successfully");
//   } catch (err) {
//     console.error("[TEST] Test failed:", err);
//     throw err;
//   }
// }

// Run tests once when component mounts
export default function AuthPage({
  onAuthSuccess,
}: {
  onAuthSuccess: (username: string) => void;
}) {
  const [mode, setMode] = useState<"login" | "register" | "forgot">("login");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [keepSignedIn, setKeepSignedIn] = useState(false);
  const [error, setError] = useState("");
  const [email, setEmail] = useState("");
  const [loading, setLoading] = useState(false);

  // Run tests once when component mounts
  // useEffect(() => {
  //   testKeyDerivation().catch(console.error);
  // }, []);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    console.log(`[handleSubmit] Mode: ${mode}`);
    console.log(`[handleSubmit] Username: ${username}`);

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

          console.log("[Register] Encrypting private keys...");
          // Encrypt private keys
          const edEncrypted = await encryptPrivateKey(
            ed25519Keypair.privateKey,
            password,
          );
          const x25519Encrypted = await encryptPrivateKey(
            x25519Keypair.privateKey,
            password,
          );
          const mldsaEncrypted = await encryptPrivateKey(
            mldsaKeypair.privateKey,
            password,
          );

          // Save encrypted keys to IndexedDB
          console.log("[Register] Saving encrypted keys to IndexedDB...");
          await saveKeyToIndexedDB(
            `${username}_ed25519_priv`,
            new Uint8Array([
              ...edEncrypted.salt,
              ...edEncrypted.iv,
              ...edEncrypted.cipher,
            ]),
          );
          await saveKeyToIndexedDB(
            `${username}_x25519_priv`,
            new Uint8Array([
              ...x25519Encrypted.salt,
              ...x25519Encrypted.iv,
              ...x25519Encrypted.cipher,
            ]),
          );
          await saveKeyToIndexedDB(
            `${username}_mldsa_priv`,
            new Uint8Array([
              ...mldsaEncrypted.salt,
              ...mldsaEncrypted.iv,
              ...mldsaEncrypted.cipher,
            ]),
          );

          // Construct key bundle for server - encode all keys as base64
          console.log("[Register] Constructing key_bundle...");
          const key_bundle = {
            preQuantum: {
              identityKemPublicKey: uint8ArrayToBase64(x25519Keypair.publicKey),
              identitySigningPublicKey: uint8ArrayToBase64(
                ed25519Keypair.publicKey,
              ),
            },
            postQuantum: {
              identityKemPublicKey: uint8ArrayToBase64(x25519Keypair.publicKey),
              identitySigningPublicKey: uint8ArrayToBase64(
                mldsaKeypair.publicKey,
              ),
            },
          };

          // Send to server (update endpoint to /api/keyhandler/register)
          console.log("[Register] Sending registration request to server...");
          console.log("[Register] Payload:", { username, key_bundle });
          const res = await fetch("/api/keyhandler/register", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ username, key_bundle }),
          });

          console.log("[Register] Server response status:", res.status);
          let errorMsg = "Registration failed";
          try {
            const data = await res.clone().json();
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
            if (keepSignedIn) {
              localStorage.setItem("drive_username", username);
            }
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
          // Get encrypted keys from IndexedDB
          const edRaw = await getKeyFromIndexedDB(`${username}_ed25519_priv`);
          const x25519Raw = await getKeyFromIndexedDB(
            `${username}_x25519_priv`,
          );
          const mldsaRaw = await getKeyFromIndexedDB(`${username}_mldsa_priv`);

          if (!edRaw || !x25519Raw || !mldsaRaw) {
            setError("No keys found for this user. Please register first.");
            setLoading(false);
            return;
          }

          // Extract salt/iv/cipher for each key
          const edSalt = edRaw.slice(0, 16);
          const edIv = edRaw.slice(16, 28);
          const edCipher = edRaw.slice(28);

          const x25519Salt = x25519Raw.slice(0, 16);
          const x25519Iv = x25519Raw.slice(16, 28);
          const x25519Cipher = x25519Raw.slice(28);

          const mldsaSalt = mldsaRaw.slice(0, 16);
          const mldsaIv = mldsaRaw.slice(16, 28);
          const mldsaCipher = mldsaRaw.slice(28);

          // Try to decrypt each key
          await decryptPrivateKey(edCipher, password, edSalt, edIv);
          await decryptPrivateKey(x25519Cipher, password, x25519Salt, x25519Iv);
          await decryptPrivateKey(mldsaCipher, password, mldsaSalt, mldsaIv);

          if (keepSignedIn) {
            localStorage.setItem("drive_username", username);
          }
          setLoading(false);
          onAuthSuccess(username);
        } catch (err: any) {
          console.error("[Login] Exception occurred:", err);
          setError("Login failed: Incorrect password or corrupted keys");
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

        {mode === "login" && (
          <div className="mb-4 flex items-center">
            <input
              type="checkbox"
              id="keepSignedIn"
              checked={keepSignedIn}
              onChange={(e) => setKeepSignedIn(e.target.checked)}
              className="h-4 w-4 rounded border-gray-300"
            />
            <label
              htmlFor="keepSignedIn"
              className="ml-2 text-sm text-gray-300"
            >
              Keep me signed in
            </label>
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
