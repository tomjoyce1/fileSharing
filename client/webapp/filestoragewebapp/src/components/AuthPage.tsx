import React, { useState, useEffect } from "react";
import { Button } from "./ui/button";
import { Input } from "./ui/input";
import { Buffer } from "buffer";
import { ml_dsa87 } from "@noble/post-quantum/ml-dsa";
import { ml_kem1024 } from "@noble/post-quantum/ml-kem";
import sodium from "libsodium-wrappers";

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
    const request = indexedDB.open("DriveKeysDB", 1);

    request.onupgradeneeded = () => {
      const db = request.result;
      if (!db.objectStoreNames.contains("keys")) {
        db.createObjectStore("keys");
      }
    };
console.log("[DB] Saving key to IndexedDB:", key, {
  type: typeof data,
  instanceOfUint8Array: data instanceof Uint8Array,
  length: data.length,
  data,
});
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
    const request = indexedDB.open("DriveKeysDB", 1);

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
  }

  if (keypair.publicKey.length !== 2592) {
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

          // Save raw private keys to IndexedDB
          await saveKeyToIndexedDB(
            `${username}_ed25519_priv`,
            ed25519Keypair.privateKey,
          );
          await saveKeyToIndexedDB(
            `${username}_x25519_priv`,
            x25519Keypair.privateKey,
          );
          await saveKeyToIndexedDB(
            `${username}_mldsa_priv`,
            mldsaKeypair.privateKey,
          );
          
          // Verify stored keys
          const mldsaVerify = await getKeyFromIndexedDB(`${username}_mldsa_priv`);
          if (!mldsaVerify || mldsaVerify.length !== 4896) {
            throw new Error(`ML-DSA key verification failed: stored length ${mldsaVerify?.length}`);
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
          const edRaw = await getKeyFromIndexedDB(`${username}_ed25519_priv`);
          const x25519Raw = await getKeyFromIndexedDB(
            `${username}_x25519_priv`,
          );
          const mldsaRaw = await getKeyFromIndexedDB(`${username}_mldsa_priv`);
          console.log("[Login] Retrieved from IndexedDB:", {
            ed: edRaw,
            x25519: x25519Raw,
            mldsa: mldsaRaw
          });
          console.log("[Login] Retrieved mldsaRaw:", mldsaRaw);
          console.log("[Login] Type:", typeof mldsaRaw);
          console.log("[Login] Is Uint8Array:", mldsaRaw instanceof Uint8Array);
          console.log("[Login] Length:", mldsaRaw?.length);

          if (!edRaw || !x25519Raw || !mldsaRaw) {
            setError("No keys found for this user. Please register first.");
            setLoading(false);
            return;
          }

          // No token logic: just set username in localStorage if keepSignedIn
          localStorage.setItem("drive_username", username);
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
