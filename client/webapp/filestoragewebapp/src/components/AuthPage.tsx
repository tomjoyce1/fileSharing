import React, { useState } from "react";
import { Button } from "~/components/ui/button";
import { Input } from "~/components/ui/input";
import sodium from "libsodium-wrappers";
import { Buffer } from "buffer";
import {
  openKeyDB,
  saveKeyToIndexedDB,
  getKeyFromIndexedDB,
  decryptPrivateKey,
} from "~/lib/crypto/KeyUtils";

// @ts-ignore
// If you get a type error for libsodium-wrappers, add a .d.ts file or use @ts-ignore as above
import { ml_dsa87 } from "@noble/post-quantum/ml-dsa";
function uint8ArrayToBase64(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64");
}

export async function deriveKeyFromPassword(
  password: string,
  salt: Uint8Array,
): Promise<CryptoKey> {
  if (typeof window === "undefined") {
    throw new Error("deriveKeyFromPassword must only be called client-side");
  }

  const argon2 = (await import("argon2-browser")).default;

  // Pass salt as Uint8Array directly (no base64 conversion)
  const argon2Params = {
    pass: password,
    salt, // <-- pass Uint8Array directly
    type: argon2.ArgonType.Argon2id,
    hashLen: 32,
    time: 3,
    mem: 64 * 1024,
    parallelism: 1,
    raw: true,
  };

  const argon2Result = await argon2.hash(argon2Params);
  console.log("argon2Result.hash type:", typeof argon2Result.hash);
  console.log("argon2Result.hash:", argon2Result.hash);
  // Defensive: handle both string and Uint8Array for hash
  let hashBytes: Uint8Array;
  if (typeof argon2Result.hash === "string") {
    // If hash is base64 string, decode to Uint8Array
    hashBytes = Uint8Array.from(atob(argon2Result.hash), (c) =>
      c.charCodeAt(0),
    );
  } else {
    hashBytes = argon2Result.hash;
  }
  return crypto.subtle.importKey("raw", hashBytes, { name: "AES-GCM" }, false, [
    "encrypt",
    "decrypt",
  ]);
}

async function encryptPrivateKey(
  privateKey: Uint8Array,
  password: string,
): Promise<{ cipher: Uint8Array; salt: Uint8Array; iv: Uint8Array }> {
  const salt = window.crypto.getRandomValues(new Uint8Array(16));
  const iv = window.crypto.getRandomValues(new Uint8Array(12));
  const key = await deriveKeyFromPassword(password, salt);
  const cipher = new Uint8Array(
    await window.crypto.subtle.encrypt(
      { name: "AES-GCM", iv },
      key,
      privateKey,
    ),
  );
  return { cipher, salt, iv };
}

// ML-DSA keygen (as in KeyHelper.ts)
async function generateMLDSAKeypair() {
  // Use 32 bytes of random for seed
  const seed = sodium.randombytes_buf(32);
  const keypair = ml_dsa87.keygen(seed);
  return {
    publicKey: keypair.publicKey,
    privateKey: keypair.secretKey,
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
  const [keepSignedIn, setKeepSignedIn] = useState(false);
  const [error, setError] = useState("");
  const [email, setEmail] = useState("");
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (mode === "register") {
      if (username.trim() && password.trim()) {
        setError("");
        setLoading(true);
        try {
          console.log("[Register] Starting sodium");
          await sodium.ready;

          console.log("[Register] Generating keypairs...");
          const edKeypair = sodium.crypto_sign_keypair();
          const x25519Keypair = sodium.crypto_kx_keypair();
          const mldsaKeypair = await generateMLDSAKeypair();

          console.log("[Register] Encrypting private keys...");
          const edEncrypted = await encryptPrivateKey(
            edKeypair.privateKey,
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

          console.log("[Register] Constructing key_bundle...");
          const key_bundle = {
            preQuantum: {
              identityKemPublicKey: Array.from(x25519Keypair.publicKey),
              identitySigningPublicKey: Array.from(edKeypair.publicKey),
            },
            postQuantum: {
              identitySigningPublicKey: Array.from(mldsaKeypair.publicKey),
            },
          };
          console.log("[Register] key_bundle:", key_bundle);

          console.log("[Register] Sending registration request to server...");
          const res = await fetch("/api/keyhandler/register", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ username, key_bundle }),
          });

          console.log("[Register] Server response status:", res.status);
          if (res.ok) {
            if (keepSignedIn) {
              localStorage.setItem("drive_username", username);
            }
            setLoading(false);
            console.log("[Register] Success");
            onAuthSuccess(username);
          } else {
            const data = await res.json();
            console.error("[Register] Server error:", data);
            setError(data.message || "Registration failed");
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
          // 1. Retrieve encrypted private keys from IndexedDB
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
          // 2. Extract salt, iv, cipher for each
          const edSalt = edRaw.slice(0, 16);
          const edIv = edRaw.slice(16, 28);
          const edCipher = edRaw.slice(28);
          const x25519Salt = x25519Raw.slice(0, 16);
          const x25519Iv = x25519Raw.slice(16, 28);
          const x25519Cipher = x25519Raw.slice(28);
          const mldsaSalt = mldsaRaw.slice(0, 16);
          const mldsaIv = mldsaRaw.slice(16, 28);
          const mldsaCipher = mldsaRaw.slice(28);
          // 3. Decrypt with password
          await decryptPrivateKey(edCipher, password, edSalt, edIv);
          await decryptPrivateKey(x25519Cipher, password, x25519Salt, x25519Iv);
          await decryptPrivateKey(mldsaCipher, password, mldsaSalt, mldsaIv);
          // If decryption succeeds, login is successful
          if (keepSignedIn) {
            localStorage.setItem("drive_username", username);
          }
          setLoading(false);
          onAuthSuccess(username);
        } catch (err: any) {
          setError("Login failed: Incorrect password or corrupted keys.");
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
              autoFocus
            />
          </div>
        )}
        {mode === "login" && (
          <div className="mb-4 flex items-center">
            <input
              type="checkbox"
              id="keepSignedIn"
              checked={keepSignedIn}
              onChange={() => setKeepSignedIn((v) => !v)}
              className="mr-2"
            />
            <label htmlFor="keepSignedIn" className="text-sm text-gray-300">
              Keep me signed in
            </label>
          </div>
        )}
        {error && <div className="mb-4 text-sm text-red-400">{error}</div>}
        <Button
          type="submit"
          className="mb-2 w-full bg-blue-600 hover:bg-blue-700"
          disabled={loading}
        >
          {loading
            ? mode === "register"
              ? "Registering..."
              : "Loading..."
            : mode === "login"
              ? "Login"
              : mode === "register"
                ? "Register"
                : "Send Reset Link"}
        </Button>
        <div className="mt-2 flex justify-between text-sm">
          {mode !== "login" && (
            <button
              type="button"
              className="text-blue-400 hover:underline"
              onClick={() => setMode("login")}
            >
              Back to Login
            </button>
          )}
          {mode === "login" && (
            <>
              <button
                type="button"
                className="text-blue-400 hover:underline"
                onClick={() => setMode("register")}
              >
                Register
              </button>
              <button
                type="button"
                className="ml-4 text-blue-400 hover:underline"
                onClick={() => setMode("forgot")}
              >
                Forgot Password?
              </button>
            </>
          )}
        </div>
      </form>
    </div>
  );
}
